package model

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileEntryValidation(t *testing.T) {
	valid := []struct {
		name  string
		entry FileEntry
	}{
		{"empty regular file", FileEntry{Path: "empty", State: FilePresent, Kind: FileRegular, Content: []byte{}, Mode: 0}},
		{"binary regular file", FileEntry{Path: "nested/data", State: FilePresent, Kind: FileRegular, Content: []byte{0, 0xff, 0x80}, Mode: 0o640}},
		{"directory", FileEntry{Path: "nested", State: FilePresent, Kind: FileDirectory, Mode: 0o750}},
		{"relative symlink", FileEntry{Path: "link", State: FilePresent, Kind: FileSymlink, LinkTarget: "../shared/config", Mode: 0}},
		{"tombstone", FileEntry{Path: "removed", State: FileDeleted}},
		{"root entry", FileEntry{Path: ".", State: FilePresent, Kind: FileDirectory, Mode: 0o700}},
	}
	for _, test := range valid {
		t.Run(test.name, func(t *testing.T) {
			assert.NoError(t, test.entry.Validate())
		})
	}
}

func TestFileEntryRejectsInvalidPathAndPayload(t *testing.T) {
	badPaths := []string{"", "/absolute", "../escape", "a/../b", "a/./b", "a//b", "a/", "C:/file", `a\b`, "a\x00b", string([]byte{0xff}), strings.Repeat("x", MaxRelativePathBytes+1)}
	for i, path := range badPaths {
		t.Run("path-"+string(rune('a'+i)), func(t *testing.T) {
			assert.Error(t, FileEntry{Path: path, State: FilePresent, Kind: FileRegular, Content: []byte{}}.Validate())
		})
	}

	invalid := []FileEntry{
		{Path: "file", State: FileState("other"), Kind: FileRegular, Content: []byte{}},
		{Path: "file", State: FilePresent, Kind: FileKind("other"), Content: []byte{}},
		{Path: "file", State: FilePresent, Kind: FileRegular, Content: nil},
		{Path: "file", State: FilePresent, Kind: FileRegular, Content: []byte{}, LinkTarget: "link"},
		{Path: "dir", State: FilePresent, Kind: FileDirectory, Content: []byte{}},
		{Path: "dir", State: FilePresent, Kind: FileDirectory, LinkTarget: "link"},
		{Path: "file", State: FilePresent, Kind: FileRegular, Content: []byte{}, Mode: 0o100644},
		{Path: "link", State: FilePresent, Kind: FileSymlink, LinkTarget: ""},
		{Path: "link", State: FilePresent, Kind: FileSymlink, LinkTarget: "/machine/path"},
		{Path: "link", State: FilePresent, Kind: FileSymlink, LinkTarget: "C:machine"},
		{Path: "link", State: FilePresent, Kind: FileSymlink, LinkTarget: `dir\file`},
		{Path: "link", State: FilePresent, Kind: FileSymlink, LinkTarget: "a\x00b"},
		{Path: "link", State: FilePresent, Kind: FileSymlink, LinkTarget: strings.Repeat("x", MaxSymlinkTargetBytes+1)},
		{Path: "link", State: FilePresent, Kind: FileSymlink, LinkTarget: "relative", Mode: 0o777},
		{Path: "removed", State: FileDeleted, Kind: FileRegular},
		{Path: "removed", State: FileDeleted, Content: []byte{}},
		{Path: "removed", State: FileDeleted, Mode: 0o600},
	}
	for i, entry := range invalid {
		t.Run("payload-"+string(rune('a'+i)), func(t *testing.T) {
			assert.Error(t, entry.Validate())
		})
	}
}

func TestSettingEntryValidation(t *testing.T) {
	valid := []SettingEntry{
		{SchemaID: "org.example.Desktop", Path: "/org/example:/", Key: "color-scheme", State: SettingPresent, Value: &VariantValue{Type: "s", Text: "'dark'"}},
		{SchemaID: "org.example.Desktop", Path: "/", Key: "enabled", State: SettingReset},
	}
	for i, entry := range valid {
		t.Run(string(rune('a'+i)), func(t *testing.T) {
			assert.NoError(t, entry.Validate())
		})
	}

	invalid := []SettingEntry{
		{SchemaID: "org.example.Desktop", Path: "/org/example/", Key: "key", State: SettingPresent},
		{SchemaID: "org.example.Desktop", Path: "/org/example/", Key: "key", State: SettingPresent, Value: &VariantValue{Type: "s"}},
		{SchemaID: "org.example.Desktop", Path: "/org/example/", Key: "key", State: SettingReset, Value: &VariantValue{Type: "s", Text: "'x'"}},
		{SchemaID: "org.example.Desktop", Path: "/org/example/", Key: "key", State: SettingState("deleted")},
		{SchemaID: "org.example.Desktop", Path: "org/example/", Key: "key", State: SettingReset},
		{SchemaID: "org.example.Desktop", Path: "/org/example", Key: "key", State: SettingReset},
		{SchemaID: "org.example.Desktop", Path: "/org//example/", Key: "key", State: SettingReset},
		{SchemaID: "org.example.Desktop", Path: "/org/example/", Key: "key/name", State: SettingReset},
		{SchemaID: "org.example.Desktop", Path: "/org/example/", Key: "key\x00", State: SettingReset},
		{SchemaID: "", Path: "/org/example/", Key: "key", State: SettingReset},
		{SchemaID: "org.example.Desktop", Path: "/org/example/", Key: "key", State: SettingPresent, Value: &VariantValue{Text: "'x'"}},
		{SchemaID: "org.example.Desktop", Path: "/org/example/", Key: "key", State: SettingPresent, Value: &VariantValue{Type: "s", Text: ""}},
		{SchemaID: "org.example.Desktop", Path: "/org/example/", Key: "key", State: SettingPresent, Value: &VariantValue{Type: "s", Text: "\x00"}},
		{SchemaID: "org.example.Desktop", Path: "/org/example/", Key: "key", State: SettingPresent, Value: &VariantValue{Type: "s", Text: string([]byte{0xff})}},
		{SchemaID: "org.example.Desktop", Path: "/org/example/", Key: "key", State: SettingPresent, Value: &VariantValue{Type: strings.Repeat("t", MaxVariantTypeBytes+1), Text: "'x'"}},
		{SchemaID: "org.example.Desktop", Path: "/org/example/", Key: "key", State: SettingPresent, Value: &VariantValue{Type: "s", Text: strings.Repeat("x", MaxVariantTextBytes+1)}},
	}
	for i, entry := range invalid {
		t.Run("invalid-"+string(rune('a'+i)), func(t *testing.T) {
			assert.Error(t, entry.Validate())
		})
	}
	require.NoError(t, (SettingEntry{SchemaID: strings.Repeat("s", MaxSettingSchemaIDBytes), Path: "/", Key: strings.Repeat("k", MaxSettingKeyBytes), State: SettingReset}).Validate())
	require.Error(t, (SettingEntry{SchemaID: strings.Repeat("s", MaxSettingSchemaIDBytes+1), Path: "/", Key: "key", State: SettingReset}).Validate())
}

func TestEntryRequiresExactlyOneSource(t *testing.T) {
	file := &FileEntry{Path: ".", State: FilePresent, Kind: FileDirectory}
	setting := &SettingEntry{SchemaID: "org.example.Desktop", Path: "/", Key: "enabled", State: SettingReset}
	assert.Error(t, (Entry{TargetID: "target"}).Validate())
	assert.Error(t, (Entry{TargetID: "target", File: file, Setting: setting}).Validate())
	assert.Error(t, (Entry{File: file}).Validate())
	assert.NoError(t, (Entry{TargetID: "target", File: file}).Validate())
}
