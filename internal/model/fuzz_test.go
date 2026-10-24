package model

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

func FuzzEntryValidate(f *testing.F) {
	seeds := []Entry{
		{TargetID: "files", File: &FileEntry{Path: "empty", State: FilePresent, Kind: FileRegular, Content: []byte{}}},
		{TargetID: "files", File: &FileEntry{Path: "nested", State: FilePresent, Kind: FileDirectory}},
		{TargetID: "files", File: &FileEntry{Path: "link", State: FilePresent, Kind: FileSymlink, LinkTarget: "../shared/config"}},
		{TargetID: "files", File: &FileEntry{Path: "removed", State: FileDeleted}},
		{TargetID: "settings", Setting: &SettingEntry{SchemaID: "org.example.Desktop", Path: "/", Key: "enabled", State: SettingReset}},
	}
	for _, entry := range seeds {
		addEntrySeed(f, entry)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, entry := range knownInvalidEntries() {
			if err := entry.Validate(); err == nil {
				t.Fatalf("known-invalid entry was accepted: %#v", entry)
			}
		}

		var entry Entry
		if err := json.Unmarshal(data, &entry); err != nil {
			return
		}
		if err := entry.Validate(); err != nil {
			return
		}
		if err := independentlyCheckEntry(entry); err != nil {
			t.Fatal(err)
		}
	})
}

func addEntrySeed(f *testing.F, entry Entry) {
	data, err := json.Marshal(entry)
	if err != nil {
		panic(err)
	}
	f.Add(data)
}

func knownInvalidEntries() []Entry {
	regular := &FileEntry{Path: "item", State: FilePresent, Kind: FileRegular, Content: []byte{}}
	setting := &SettingEntry{SchemaID: "org.example.Desktop", Path: "/", Key: "enabled", State: SettingReset}
	tooLongPath := strings.Repeat("a", MaxRelativePathBytes+1)
	tooLongTarget := strings.Repeat("t", MaxTargetIDBytes+1)
	return []Entry{
		{},
		{TargetID: "", File: regular},
		{TargetID: tooLongTarget, File: regular},
		{TargetID: "files\x00", File: regular},
		{TargetID: "files", File: &FileEntry{Path: "item", State: FilePresent, Kind: FileRegular}},
		{TargetID: "files", File: &FileEntry{Path: "../outside", State: FilePresent, Kind: FileRegular, Content: []byte{}}},
		{TargetID: "files", File: &FileEntry{Path: "nul\x00path", State: FilePresent, Kind: FileRegular, Content: []byte{}}},
		{TargetID: "files", File: &FileEntry{Path: tooLongPath, State: FilePresent, Kind: FileRegular, Content: []byte{}}},
		{TargetID: "files", File: &FileEntry{Path: "item", State: FilePresent, Kind: FileRegular, Content: []byte{}, Mode: 0o7777}},
		{TargetID: "files", File: &FileEntry{Path: "item", State: FilePresent, Kind: FileDirectory, Mode: 0o7777}},
		{TargetID: "files", File: &FileEntry{Path: "link", State: FilePresent, Kind: FileSymlink, LinkTarget: "../shared", Content: []byte{}}},
		{TargetID: "files", File: regular, Setting: setting},
		{TargetID: "settings", Setting: &SettingEntry{SchemaID: "org.example.Desktop", Path: "relative/", Key: "enabled", State: SettingReset}},
		{TargetID: "settings", Setting: &SettingEntry{SchemaID: "org.example.Desktop", Path: "/", Key: "enabled/x", State: SettingReset}},
	}
}

func independentlyCheckEntry(entry Entry) error {
	if !oracleTextValid(entry.TargetID, MaxTargetIDBytes) {
		return fmt.Errorf("accepted entry has an invalid target id: %q", entry.TargetID)
	}
	if (entry.File == nil) == (entry.Setting == nil) {
		return fmt.Errorf("accepted entry does not carry exactly one payload: %#v", entry)
	}
	if entry.File == nil {
		return nil
	}
	file := entry.File
	if !oracleTextValid(file.Path, MaxRelativePathBytes) {
		return fmt.Errorf("accepted file path violates text bounds: %q", file.Path)
	}
	pathDrivePrefix := len(file.Path) >= 2 && ((file.Path[0] >= 'a' && file.Path[0] <= 'z') || (file.Path[0] >= 'A' && file.Path[0] <= 'Z')) && file.Path[1] == ':'
	if file.Path == "" || strings.HasPrefix(file.Path, "/") || strings.ContainsRune(file.Path, '\\') || pathDrivePrefix {
		return fmt.Errorf("accepted file path is not relative: %q", file.Path)
	}
	if file.Path != "." {
		for _, segment := range strings.Split(file.Path, "/") {
			if segment == "" || segment == "." || segment == ".." {
				return fmt.Errorf("accepted file path has an invalid segment: %q", file.Path)
			}
		}
	}
	if file.State != FilePresent {
		return nil
	}
	if file.Mode&^uint32(0o777) != 0 {
		return fmt.Errorf("accepted file has out-of-range permission bits: %o", file.Mode)
	}
	switch file.Kind {
	case FileRegular:
		if file.Content == nil || file.LinkTarget != "" {
			return fmt.Errorf("accepted regular file has an invalid payload: %#v", file)
		}
	case FileDirectory:
		if file.Content != nil || file.LinkTarget != "" {
			return fmt.Errorf("accepted directory has an invalid payload: %#v", file)
		}
	case FileSymlink:
		drivePrefix := oracleDrivePrefix(file.LinkTarget)
		if file.Content != nil || file.Mode != 0 || file.LinkTarget == "" || strings.HasPrefix(file.LinkTarget, "/") || strings.ContainsRune(file.LinkTarget, '\\') || drivePrefix {
			return fmt.Errorf("accepted symlink has an invalid payload: %#v", file)
		}
		if !oracleTextValid(file.LinkTarget, MaxSymlinkTargetBytes) {
			return fmt.Errorf("accepted symlink target violates text bounds: %q", file.LinkTarget)
		}
	}
	return nil
}

func FuzzSnapshotValidate(f *testing.F) {
	seeds := []Snapshot{
		{Version: SnapshotVersion},
		{
			Version: SnapshotVersion,
			Targets: []Target{{ID: "files", Source: SourceFiles, SourceVersion: SourceVersion, Root: &FileRoot{Base: RootHome, Path: "config", Kind: SelectionDirectory}}},
			Entries: []Entry{{TargetID: "files", File: &FileEntry{Path: "nested/file", State: FilePresent, Kind: FileRegular, Content: []byte("data")}}},
		},
		{
			Version: SnapshotVersion,
			Targets: []Target{{ID: "settings", Source: SourceGNOME, SourceVersion: SourceVersion}},
			Entries: []Entry{{TargetID: "settings", Setting: &SettingEntry{SchemaID: "org.example.Desktop", Path: "/", Key: "enabled", State: SettingReset}}},
		},
	}
	for _, snapshot := range seeds {
		data, err := json.Marshal(snapshot)
		if err != nil {
			panic(err)
		}
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, snapshot := range knownInvalidSnapshots() {
			if err := snapshot.Validate(); err == nil {
				t.Fatalf("known-invalid snapshot was accepted: %#v", snapshot)
			}
		}

		var snapshot Snapshot
		if err := json.Unmarshal(data, &snapshot); err != nil {
			return
		}
		if err := snapshot.Validate(); err != nil {
			return
		}
		if err := independentlyCheckSnapshot(snapshot); err != nil {
			t.Fatal(err)
		}
	})
}

func knownInvalidSnapshots() []Snapshot {
	files := Target{ID: "files", Source: SourceFiles, SourceVersion: SourceVersion, Root: &FileRoot{Base: RootHome, Path: "config", Kind: SelectionDirectory}}
	gnome := Target{ID: "settings", Source: SourceGNOME, SourceVersion: SourceVersion}
	fileEntry := Entry{TargetID: "files", File: &FileEntry{Path: "item", State: FilePresent, Kind: FileRegular, Content: []byte{}}}
	settingEntry := Entry{TargetID: "settings", Setting: &SettingEntry{SchemaID: "org.example.Desktop", Path: "/", Key: "enabled", State: SettingReset}}
	wrongSetting := Entry{TargetID: "files", Setting: settingEntry.Setting}
	wrongFile := Entry{TargetID: "settings", File: fileEntry.File}
	return []Snapshot{
		{Version: SnapshotVersion, Targets: []Target{files, files}},
		{Version: SnapshotVersion, Targets: []Target{files}, Entries: []Entry{{TargetID: "missing", File: fileEntry.File}}},
		{Version: SnapshotVersion, Targets: []Target{files}, Entries: []Entry{wrongSetting}},
		{Version: SnapshotVersion, Targets: []Target{gnome}, Entries: []Entry{wrongFile}},
		{Version: SnapshotVersion, Targets: []Target{files}, Entries: []Entry{fileEntry, fileEntry}},
		{Version: SnapshotVersion + 1, Targets: []Target{files}},
		{Version: 0},
		{Version: SnapshotVersion, Targets: []Target{files}, Entries: []Entry{
			{TargetID: "files", File: &FileEntry{Path: "a", State: FilePresent, Kind: FileRegular, Content: []byte{}}},
			{TargetID: "files", File: &FileEntry{Path: "a/b", State: FilePresent, Kind: FileRegular, Content: []byte{}}},
		}},
		{Version: SnapshotVersion, Targets: []Target{
			{ID: "single", Source: SourceFiles, SourceVersion: SourceVersion, Root: &FileRoot{Base: RootHome, Path: "file", Kind: SelectionFile}},
		}, Entries: []Entry{{TargetID: "single", File: &FileEntry{Path: "file", State: FilePresent, Kind: FileRegular, Content: []byte{}}}}},
		{Version: SnapshotVersion, Targets: []Target{files}, Entries: []Entry{
			{TargetID: "files", File: &FileEntry{Path: ".", State: FilePresent, Kind: FileRegular, Content: []byte{}}},
			{TargetID: "files", File: &FileEntry{Path: "a/b", State: FilePresent, Kind: FileRegular, Content: []byte{}}},
		}},
		{Version: SnapshotVersion, Targets: []Target{{ID: "files", Source: SourceFiles, SourceVersion: SourceVersion + 1, Root: &FileRoot{Base: RootHome, Path: "x", Kind: SelectionDirectory}}}},
		{Version: SnapshotVersion, Targets: []Target{{ID: "files", Source: SourceFiles, SourceVersion: SourceVersion, Root: &FileRoot{Base: RootBase("tmp"), Path: "x", Kind: SelectionDirectory}}}},
		{Version: SnapshotVersion, Targets: []Target{{ID: strings.Repeat("t", MaxTargetIDBytes+1), Source: SourceFiles, SourceVersion: SourceVersion, Root: &FileRoot{Base: RootHome, Path: "x", Kind: SelectionDirectory}}}},
		{Version: SnapshotVersion, Targets: []Target{{ID: "files", Source: SourceFiles, SourceVersion: SourceVersion, Root: &FileRoot{Base: RootHome, Path: "../x", Kind: SelectionDirectory}}}},
		{Version: SnapshotVersion, Targets: []Target{{ID: "files", Source: SourceFiles, SourceVersion: SourceVersion, Root: &FileRoot{Base: RootHome, Path: ".", Kind: SelectionFile}}}},
		{Version: SnapshotVersion, Targets: []Target{{ID: "files", Source: SourceFiles, SourceVersion: SourceVersion, Root: &FileRoot{Base: RootHome, Path: "x", Kind: SelectionKind("socket")}}}},
	}
}

type independentEntryIdentity struct {
	targetID string
	source   SourceKind
	filePath string
	schemaID string
	path     string
	key      string
}

func independentlyCheckSnapshot(snapshot Snapshot) error {
	if snapshot.Version != SnapshotVersion {
		return fmt.Errorf("accepted snapshot has an unsupported version: %d", snapshot.Version)
	}
	targets := make(map[string]Target, len(snapshot.Targets))
	for _, target := range snapshot.Targets {
		if err := oracleTargetValid(target); err != nil {
			return fmt.Errorf("accepted snapshot has an invalid target %q: %w", target.ID, err)
		}
		if _, exists := targets[target.ID]; exists {
			return fmt.Errorf("accepted snapshot has duplicate target id %q", target.ID)
		}
		targets[target.ID] = target
	}
	identities := make(map[independentEntryIdentity]struct{}, len(snapshot.Entries))
	for _, entry := range snapshot.Entries {
		identity := independentEntryIdentity{targetID: entry.TargetID}
		if entry.File != nil {
			identity.source = SourceFiles
			identity.filePath = entry.File.Path
		} else if entry.Setting != nil {
			identity.source = SourceGNOME
			identity.schemaID = entry.Setting.SchemaID
			identity.path = entry.Setting.Path
			identity.key = entry.Setting.Key
		}
		if _, exists := identities[identity]; exists {
			return fmt.Errorf("accepted snapshot has duplicate entry identity: %#v", identity)
		}
		identities[identity] = struct{}{}

		target, exists := targets[entry.TargetID]
		if !exists {
			return fmt.Errorf("accepted entry references missing target %q", entry.TargetID)
		}
		if entry.File != nil {
			if target.Source != SourceFiles || target.Root == nil {
				return fmt.Errorf("accepted file entry has mismatched target: %#v", entry)
			}
			if target.Root.Kind == SelectionFile && entry.File.Path != "." {
				return fmt.Errorf("accepted single-file entry escapes its identity: %#v", entry)
			}
		} else if entry.Setting != nil && target.Source != SourceGNOME {
			return fmt.Errorf("accepted setting entry has mismatched target: %#v", entry)
		}
	}
	return independentlyCheckFileTrees(snapshot.Entries)
}

func independentlyCheckFileTrees(entries []Entry) error {
	present := make(map[string]map[string]FileKind)
	for _, entry := range entries {
		if entry.File == nil || entry.File.State != FilePresent {
			continue
		}
		if present[entry.TargetID] == nil {
			present[entry.TargetID] = make(map[string]FileKind)
		}
		present[entry.TargetID][entry.File.Path] = entry.File.Kind
	}
	for _, paths := range present {
		for path := range paths {
			if path == "." {
				continue
			}
			ancestor := "."
			for _, segment := range strings.Split(path, "/") {
				if kind, exists := paths[ancestor]; exists && kind != FileDirectory {
					return fmt.Errorf("accepted present file has a non-directory ancestor: %q via %q", path, ancestor)
				}
				if ancestor == "." {
					ancestor = segment
				} else {
					ancestor += "/" + segment
				}
			}
		}
	}
	return nil
}

func oracleTextValid(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && utf8.ValidString(value) && !strings.ContainsRune(value, '\x00')
}

func oracleDrivePrefix(path string) bool {
	return len(path) >= 2 && ((path[0] >= 'a' && path[0] <= 'z') || (path[0] >= 'A' && path[0] <= 'Z')) && path[1] == ':'
}

func oracleRelativePathValid(path string, allowRoot bool) bool {
	if !oracleTextValid(path, MaxRelativePathBytes) || strings.ContainsRune(path, '\\') || strings.HasPrefix(path, "/") || oracleDrivePrefix(path) {
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

func oracleTargetValid(target Target) error {
	if !oracleTextValid(target.ID, MaxTargetIDBytes) {
		return fmt.Errorf("invalid target identifier: %q", target.ID)
	}
	if target.SourceVersion != SourceVersion {
		return fmt.Errorf("unsupported target source version: %d", target.SourceVersion)
	}
	switch target.Source {
	case SourceFiles:
		if target.Root == nil {
			return fmt.Errorf("file target without a root: %q", target.ID)
		}
		if target.Root.Base != RootHome && target.Root.Base != RootXDGConfig {
			return fmt.Errorf("unsupported root base: %q", target.Root.Base)
		}
		if !oracleRelativePathValid(target.Root.Path, true) {
			return fmt.Errorf("invalid selection path: %q", target.Root.Path)
		}
		switch target.Root.Kind {
		case SelectionFile:
			if target.Root.Path == "." {
				return fmt.Errorf("single-file target names the base directory: %q", target.ID)
			}
		case SelectionDirectory:
		default:
			return fmt.Errorf("unsupported selection kind: %q", target.Root.Kind)
		}
	case SourceGNOME:
		if target.Root != nil {
			return fmt.Errorf("setting target carries a filesystem root: %q", target.ID)
		}
	default:
		return fmt.Errorf("unsupported target source: %q", target.Source)
	}
	return nil
}

func TestIndependentlyCheckSnapshotScopesTreesPerTarget(t *testing.T) {
	snapshot := Snapshot{
		Version: SnapshotVersion,
		Targets: []Target{
			{ID: "a", Source: SourceFiles, SourceVersion: SourceVersion, Root: &FileRoot{Base: RootHome, Path: "x", Kind: SelectionDirectory}},
			{ID: "b", Source: SourceFiles, SourceVersion: SourceVersion, Root: &FileRoot{Base: RootHome, Path: "y", Kind: SelectionDirectory}},
		},
		Entries: []Entry{
			{TargetID: "a", File: &FileEntry{Path: "a", State: FilePresent, Kind: FileRegular, Content: []byte{}}},
			{TargetID: "b", File: &FileEntry{Path: "a/b", State: FilePresent, Kind: FileRegular, Content: []byte{}}},
		},
	}
	if err := snapshot.Validate(); err != nil {
		t.Fatalf("production rejected a per-target-scoped snapshot: %v", err)
	}
	if err := independentlyCheckSnapshot(snapshot); err != nil {
		t.Fatalf("oracle rejected a per-target-scoped snapshot: %v", err)
	}
}

func TestIndependentlyCheckSnapshotRejectsRootAncestorFile(t *testing.T) {
	snapshot := Snapshot{
		Version: SnapshotVersion,
		Targets: []Target{{ID: "files", Source: SourceFiles, SourceVersion: SourceVersion, Root: &FileRoot{Base: RootHome, Path: "config", Kind: SelectionDirectory}}},
		Entries: []Entry{
			{TargetID: "files", File: &FileEntry{Path: ".", State: FilePresent, Kind: FileRegular, Content: []byte{}}},
			{TargetID: "files", File: &FileEntry{Path: "a/b", State: FilePresent, Kind: FileRegular, Content: []byte{}}},
		},
	}
	if err := snapshot.Validate(); err == nil {
		t.Fatal("production accepted a non-directory root ancestor")
	}
	if err := independentlyCheckSnapshot(snapshot); err == nil {
		t.Fatal("oracle accepted a non-directory root ancestor")
	}
}
