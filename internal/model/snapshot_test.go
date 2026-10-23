package model

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func filesTarget(id string, kind SelectionKind) Target {
	return Target{ID: id, Source: SourceFiles, SourceVersion: SourceVersion, Root: &FileRoot{Base: RootHome, Path: "config", Kind: kind}}
}

func gnomeTarget(id string) Target {
	return Target{ID: id, Source: SourceGNOME, SourceVersion: SourceVersion}
}

func fileEntry(targetID, path string, kind FileKind, state FileState) Entry {
	entry := FileEntry{Path: path, Kind: kind, State: state}
	if state == FilePresent {
		switch kind {
		case FileRegular:
			entry.Content = []byte("data")
		case FileSymlink:
			entry.LinkTarget = "relative-target"
		}
	}
	return Entry{TargetID: targetID, File: &entry}
}

func basicSnapshot(entries ...Entry) Snapshot {
	return Snapshot{Version: SnapshotVersion, Targets: []Target{filesTarget("files", SelectionDirectory)}, Entries: entries}
}

func TestSnapshotValidation(t *testing.T) {
	snapshot := Snapshot{
		Version: SnapshotVersion,
		Targets: []Target{filesTarget("files", SelectionDirectory), gnomeTarget("settings")},
		Entries: []Entry{
			fileEntry("files", "config", FileRegular, FilePresent),
			{TargetID: "settings", Setting: &SettingEntry{SchemaID: "org.example.Desktop", Path: "/", Key: "enabled", State: SettingReset}},
		},
	}
	assert.NoError(t, snapshot.Validate())
	assert.NoError(t, (Snapshot{Version: SnapshotVersion}).Validate())
}

func TestSnapshotRejectsInvalidReferencesAndIdentity(t *testing.T) {
	valid := fileEntry("files", "config", FileRegular, FilePresent)
	setting := Entry{TargetID: "settings", Setting: &SettingEntry{SchemaID: "org.example.Desktop", Path: "/", Key: "enabled", State: SettingReset}}
	invalid := []Snapshot{
		{Version: SnapshotVersion + 1, Targets: []Target{{}}, Entries: []Entry{{}}},
		{Version: SnapshotVersion, Targets: []Target{filesTarget("files", SelectionDirectory), filesTarget("files", SelectionDirectory)}},
		{Version: SnapshotVersion, Targets: []Target{filesTarget("files", SelectionDirectory)}, Entries: []Entry{fileEntry("unknown", "config", FileRegular, FilePresent)}},
		{Version: SnapshotVersion, Targets: []Target{filesTarget("files", SelectionDirectory)}, Entries: []Entry{setting}},
		{Version: SnapshotVersion, Targets: []Target{gnomeTarget("settings")}, Entries: []Entry{valid}},
		{Version: SnapshotVersion, Targets: []Target{filesTarget("single", SelectionFile)}, Entries: []Entry{fileEntry("single", "child", FileRegular, FilePresent)}},
		basicSnapshot(valid, fileEntry("files", "config", FileDirectory, FilePresent)),
	}
	for i, snapshot := range invalid {
		t.Run(string(rune('a'+i)), func(t *testing.T) {
			assert.Error(t, snapshot.Validate())
		})
	}
	assert.NoError(t, (Snapshot{Version: SnapshotVersion, Targets: []Target{filesTarget("single", SelectionFile)}, Entries: []Entry{fileEntry("single", ".", FileRegular, FilePresent)}}).Validate())
}

func TestSnapshotRejectsPresentNonDirectoryAncestors(t *testing.T) {
	cases := []struct {
		name    string
		entries []Entry
	}{
		{"regular ancestor", []Entry{fileEntry("files", "a", FileRegular, FilePresent), fileEntry("files", "a/b", FileRegular, FilePresent)}},
		{"symlink ancestor", []Entry{fileEntry("files", "a", FileSymlink, FilePresent), fileEntry("files", "a/b", FileRegular, FilePresent)}},
		{"selected root regular ancestor", []Entry{fileEntry("files", ".", FileRegular, FilePresent), fileEntry("files", "a", FileRegular, FilePresent)}},
		{"selected root symlink ancestor", []Entry{fileEntry("files", ".", FileSymlink, FilePresent), fileEntry("files", "a", FileRegular, FilePresent)}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			assert.Error(t, basicSnapshot(test.entries...).Validate())
		})
	}
}

func TestSnapshotAllowsDirectoriesNearMissesAndTombstones(t *testing.T) {
	cases := []struct {
		name    string
		entries []Entry
	}{
		{"directory ancestor", []Entry{fileEntry("files", "a", FileDirectory, FilePresent), fileEntry("files", "a/b", FileRegular, FilePresent)}},
		{"component prefix near miss", []Entry{fileEntry("files", "a", FileRegular, FilePresent), fileEntry("files", "ab/child", FileRegular, FilePresent)}},
		{"present replacement and deleted child", []Entry{fileEntry("files", "a", FileRegular, FilePresent), fileEntry("files", "a/b", "", FileDeleted)}},
		{"deleted ancestor and present child", []Entry{fileEntry("files", "a", "", FileDeleted), fileEntry("files", "a/b", FileRegular, FilePresent)}},
		{"all tombstones", []Entry{fileEntry("files", "a", "", FileDeleted), fileEntry("files", "a/b", "", FileDeleted)}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			assert.NoError(t, basicSnapshot(test.entries...).Validate())
		})
	}
}

func TestSnapshotTreeChecksArePerTarget(t *testing.T) {
	snapshot := Snapshot{
		Version: SnapshotVersion,
		Targets: []Target{filesTarget("first", SelectionDirectory), filesTarget("second", SelectionDirectory)},
		Entries: []Entry{
			fileEntry("first", "a", FileRegular, FilePresent),
			fileEntry("second", "a/b", FileRegular, FilePresent),
		},
	}
	assert.NoError(t, snapshot.Validate())
}

func TestSnapshotJSONRoundTripPreservesModelData(t *testing.T) {
	snapshot := Snapshot{
		Version: SnapshotVersion,
		Targets: []Target{filesTarget("files", SelectionDirectory), gnomeTarget("settings")},
		Entries: []Entry{
			{TargetID: "files", File: &FileEntry{Path: "empty", State: FilePresent, Kind: FileRegular, Content: []byte{}, Mode: 0}},
			{TargetID: "files", File: &FileEntry{Path: "binary", State: FilePresent, Kind: FileRegular, Content: []byte{0, 0xff, 0x80}, Mode: 0o640}},
			{TargetID: "files", File: &FileEntry{Path: "directory", State: FilePresent, Kind: FileDirectory, Mode: 0o750}},
			{TargetID: "files", File: &FileEntry{Path: "link", State: FilePresent, Kind: FileSymlink, LinkTarget: "../destination"}},
			{TargetID: "files", File: &FileEntry{Path: "deleted", State: FileDeleted}},
			{TargetID: "settings", Setting: &SettingEntry{SchemaID: "org.example.Desktop", Path: "/org/example:/", Key: "mode", State: SettingPresent, Value: &VariantValue{Type: "s", Text: "'dark'"}}},
			{TargetID: "settings", Setting: &SettingEntry{SchemaID: "org.example.Desktop", Path: "/", Key: "enabled", State: SettingReset}},
		},
	}
	require.NoError(t, snapshot.Validate())
	encoded, err := json.Marshal(snapshot)
	require.NoError(t, err)
	var decoded Snapshot
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	require.Equal(t, snapshot, decoded)
	require.NoError(t, decoded.Validate())
	require.NotNil(t, decoded.Entries[0].File.Content)
	require.Nil(t, decoded.Entries[4].File.Content)
	require.Nil(t, decoded.Entries[6].Setting.Value)
}
