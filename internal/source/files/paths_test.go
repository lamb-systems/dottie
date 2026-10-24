package files

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJoinRelative(t *testing.T) {
	for _, test := range []struct {
		parent string
		name   string
		want   string
		bad    bool
	}{
		{parent: ".", name: "child", want: "child"},
		{parent: "a/b", name: "child", want: "a/b/child"},
		{parent: "a", name: "../b", bad: true},
		{parent: "a", name: "b/c", bad: true},
		{parent: "a//b", name: "child", bad: true},
		{parent: "/abs", name: "child", bad: true},
		{parent: ".", name: "bad\\name", bad: true},
		{parent: ".", name: "bad\x00name", bad: true},
		{parent: ".", name: strings.Repeat("a", 4097), bad: true},
	} {
		got, err := JoinRelative(test.parent, test.name)
		if test.bad {
			assert.Error(t, err)
			continue
		}
		require.NoError(t, err)
		assert.Equal(t, test.want, got)
	}
}

func TestIsWithinUsesPathComponents(t *testing.T) {
	for _, test := range []struct {
		root      string
		candidate string
		within    bool
	}{
		{root: ".", candidate: "a", within: true},
		{root: "a", candidate: "a", within: true},
		{root: "a", candidate: "a/b", within: true},
		{root: "a", candidate: "ab", within: false},
		{root: "a", candidate: "a-b/file", within: false},
		{root: "a", candidate: "../a", within: false},
		{root: "/", candidate: "a", within: false},
	} {
		assert.Equal(t, test.within, IsWithin(test.root, test.candidate), "%q within %q", test.candidate, test.root)
	}
}

func TestLexicalResolve(t *testing.T) {
	for _, test := range []struct {
		dir     string
		target  string
		want    string
		escapes bool
	}{
		{dir: ".", target: "file", want: "file"},
		{dir: "a", target: "../sibling", want: "sibling"},
		{dir: "a/b", target: "../../sibling", want: "sibling"},
		{dir: "a/b", target: "../../../escape", escapes: true},
		{dir: ".", target: "../escape", escapes: true},
		{dir: "a", target: "./b/../c", want: "a/c"},
		{dir: "a", target: "/absolute", escapes: true},
		{dir: "a", target: "C:/absolute", escapes: true},
		{dir: "a", target: "a//b", escapes: true},
		{dir: "a", target: `a\\b`, escapes: true},
		{dir: "a", target: "bad\x00name", escapes: true},
		{dir: "a", target: strings.Repeat("a", 4097), escapes: true},
	} {
		got, escapes := LexicalResolve(test.dir, test.target)
		assert.Equal(t, test.want, got)
		assert.Equal(t, test.escapes, escapes, "%q from %q", test.target, test.dir)
	}
}

func TestSegments(t *testing.T) {
	assert.Empty(t, Segments("."))
	assert.Equal(t, []string{"a", "b", "c"}, Segments("a/b/c"))
	assert.Nil(t, Segments("a/../b"))
}
