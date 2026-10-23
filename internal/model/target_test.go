package model

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTargetValidation(t *testing.T) {
	tests := []struct {
		name   string
		target Target
	}{
		{
			name:   "home directory",
			target: Target{ID: "editor", Source: SourceFiles, SourceVersion: SourceVersion, Root: &FileRoot{Base: RootHome, Path: ".", Kind: SelectionDirectory}},
		},
		{
			name:   "xdg config file",
			target: Target{ID: "editor-config", Source: SourceFiles, SourceVersion: SourceVersion, Root: &FileRoot{Base: RootXDGConfig, Path: "editor/config.toml", Kind: SelectionFile}},
		},
		{
			name:   "GNOME",
			target: Target{ID: "desktop", Source: SourceGNOME, SourceVersion: SourceVersion},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.NoError(t, test.target.Validate())
		})
	}
}

func TestTargetRejectsInvalidShapes(t *testing.T) {
	validFiles := Target{ID: "editor", Source: SourceFiles, SourceVersion: SourceVersion, Root: &FileRoot{Base: RootHome, Path: "config", Kind: SelectionDirectory}}
	validGNOME := Target{ID: "desktop", Source: SourceGNOME, SourceVersion: SourceVersion}
	invalid := []Target{
		{},
		{ID: "editor", Source: SourceKind("other"), SourceVersion: SourceVersion},
		{ID: "editor", Source: SourceFiles, SourceVersion: SourceVersion},
		{ID: "editor", Source: SourceFiles, SourceVersion: SourceVersion, Root: &FileRoot{Base: RootBase("other"), Path: "config", Kind: SelectionDirectory}},
		{ID: "editor", Source: SourceFiles, SourceVersion: SourceVersion, Root: &FileRoot{Base: RootHome, Path: "config", Kind: SelectionKind("other")}},
		{ID: "desktop", Source: SourceGNOME, SourceVersion: SourceVersion, Root: &FileRoot{Base: RootHome, Path: "config", Kind: SelectionDirectory}},
	}
	for i, target := range invalid {
		t.Run(string(rune('a'+i)), func(t *testing.T) {
			assert.Error(t, target.Validate())
		})
	}

	badRoots := []FileRoot{
		{Base: RootHome, Path: "", Kind: SelectionDirectory},
		{Base: RootHome, Path: ".", Kind: SelectionFile},
		{Base: RootHome, Path: "/absolute", Kind: SelectionDirectory},
		{Base: RootHome, Path: "../escape", Kind: SelectionDirectory},
		{Base: RootHome, Path: "nested/./file", Kind: SelectionDirectory},
		{Base: RootHome, Path: "nested//file", Kind: SelectionDirectory},
		{Base: RootHome, Path: "C:/file", Kind: SelectionDirectory},
		{Base: RootHome, Path: `nested\file`, Kind: SelectionDirectory},
		{Base: RootHome, Path: "nul\x00path", Kind: SelectionDirectory},
		{Base: RootHome, Path: string([]byte{0xff}), Kind: SelectionDirectory},
		{Base: RootHome, Path: strings.Repeat("x", MaxRelativePathBytes+1), Kind: SelectionDirectory},
	}
	for i, root := range badRoots {
		t.Run(string(rune('a'+i)), func(t *testing.T) {
			assert.Error(t, root.Validate())
		})
	}

	badIDs := []string{"", "nul\x00id", string([]byte{0xff}), strings.Repeat("x", MaxTargetIDBytes+1)}
	for i, id := range badIDs {
		t.Run("id-"+string(rune('a'+i)), func(t *testing.T) {
			assert.Error(t, Target{ID: id, Source: validFiles.Source, SourceVersion: SourceVersion, Root: validFiles.Root}.Validate())
		})
	}
	assert.Error(t, Target{ID: validFiles.ID, Source: validFiles.Source, SourceVersion: SourceVersion + 1, Root: validFiles.Root}.Validate())
	assert.NoError(t, validGNOME.Validate())
}

func TestTargetIdentifierLengthBoundary(t *testing.T) {
	target := Target{ID: strings.Repeat("x", MaxTargetIDBytes), Source: SourceGNOME, SourceVersion: SourceVersion}
	require.NoError(t, target.Validate())
}
