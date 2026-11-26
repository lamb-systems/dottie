package publication

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ipfs/go-cid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/model"
)

func TestSnapshotRecordRefusesEmptySegments(t *testing.T) {
	record := fixtureSnapshotValue(t)
	record.Segments = nil
	encoded, err := EncodeSnapshot(record)
	assert.Nil(t, encoded)
	requireViolation(t, err, ErrInvalidRecord, "segments", "empty")

	value := independentSnapshotValue(t, fixtureSnapshotValue(t))
	value["segments"] = []any{}
	decoded, err := DecodeSnapshot(testCBOR(value))
	assert.Equal(t, SnapshotRecord{}, decoded)
	requireViolation(t, err, ErrInvalidRecord, "segments", "empty")
}

func TestSnapshotRecordFileSetEncodingRoundTripsCanonically(t *testing.T) {
	record := fixtureFileSetRecord(t)
	encoded, err := EncodeSnapshot(record)
	require.NoError(t, err)
	assert.Equal(t, independentFileSetBytes(t, record), encoded)

	decoded, err := DecodeSnapshot(encoded)
	require.NoError(t, err)
	assert.Equal(t, record, decoded)
	assert.Nil(t, blobOf(decoded).CID)
	assert.Empty(t, blobOf(decoded).MIMEType)

	reencoded, err := EncodeSnapshot(decoded)
	require.NoError(t, err)
	assert.Equal(t, encoded, reencoded)

	recordCID, err := RecordCID(encoded)
	require.NoError(t, err)
	identifier, err := cid.Cast(recordCID)
	require.NoError(t, err)
	assert.Equal(t, cid.NewCidV1(cid.DagCBOR, mustHash(t, encoded)).String(), identifier.String())
}

func TestSnapshotRecordPackedEncodingIsUnchangedByTheUnion(t *testing.T) {
	payload := []byte("union canary payload")
	record, encoded := fixtureSnapshot(t, payload, 3, independentCID(t, []byte("union canary parent"), cid.DagCBOR), 2)
	assert.Equal(t, independentSnapshotBytes(t, record), encoded)
	assert.Nil(t, entriesOf(record))

	decoded, err := DecodeSnapshot(encoded)
	require.NoError(t, err)
	assert.Equal(t, record, decoded)
	reencoded, err := EncodeSnapshot(decoded)
	require.NoError(t, err)
	assert.Equal(t, encoded, reencoded)
}

func TestSnapshotRecordRefusesMalformedFileSetEntries(t *testing.T) {
	cases := []struct {
		name   string
		mutate func([]SnapshotEntry)
		field  string
		reason string
	}{
		{name: "absolute path", mutate: func(entries []SnapshotEntry) {
			entries[0].Path = "/etc/passwd"
		}, field: "entries.path", reason: "absolute"},
		{name: "drive prefix path", mutate: func(entries []SnapshotEntry) {
			entries[0].Path = "C:/init.lua"
		}, field: "entries.path", reason: "absolute"},
		{name: "parent segment", mutate: func(entries []SnapshotEntry) {
			entries[0].Path = "lua/../init.lua"
		}, field: "entries.path", reason: "dot_segment"},
		{name: "root path", mutate: func(entries []SnapshotEntry) {
			entries[0].Path = "."
		}, field: "entries.path", reason: "dot_segment"},
		{name: "empty segment", mutate: func(entries []SnapshotEntry) {
			entries[0].Path = "lua//init.lua"
		}, field: "entries.path", reason: "empty_segment"},
		{name: "empty path", mutate: func(entries []SnapshotEntry) {
			entries[0].Path = ""
		}, field: "entries.path", reason: "length"},
		{name: "overlong path", mutate: func(entries []SnapshotEntry) {
			entries[0].Path = strings.Repeat("a", MaxEntryPathBytes+1)
		}, field: "entries.path", reason: "length"},
		{name: "nul path", mutate: func(entries []SnapshotEntry) {
			entries[0].Path = "lua/\x00init.lua"
		}, field: "entries.path", reason: "text"},
		{name: "backslash path", mutate: func(entries []SnapshotEntry) {
			entries[0].Path = `lua\init.lua`
		}, field: "entries.path", reason: "text"},
		{name: "duplicate path", mutate: func(entries []SnapshotEntry) {
			entries[1].Path = entries[0].Path
		}, field: "entries.path", reason: "duplicate"},
		{name: "unsorted path", mutate: func(entries []SnapshotEntry) {
			entries[0].Path = "zzz.lua"
		}, field: "entries.path", reason: "order"},
		{name: "unsupported mode", mutate: func(entries []SnapshotEntry) {
			entries[0].Mode = 0o755
		}, field: "entries.mode", reason: "unsupported"},
		{name: "absent mode", mutate: func(entries []SnapshotEntry) {
			entries[0].Mode = 0
		}, field: "entries.mode", reason: "unsupported"},
		{name: "directory kind", mutate: func(entries []SnapshotEntry) {
			entries[0].Kind = "directory"
		}, field: "entries.kind", reason: "unsupported"},
		{name: "absent kind", mutate: func(entries []SnapshotEntry) {
			entries[0].Kind = ""
		}, field: "entries.kind", reason: "unsupported"},
		{name: "size mismatch", mutate: func(entries []SnapshotEntry) {
			entries[0].Size++
		}, field: "entries.size", reason: "mismatch"},
		{name: "zero size", mutate: func(entries []SnapshotEntry) {
			entries[0].Size = 0
			entries[0].Blob.Size = 0
		}, field: "entries.size", reason: "range"},
		{name: "unsupported blob media type", mutate: func(entries []SnapshotEntry) {
			entries[0].Blob.MIMEType = "image/png"
		}, field: "entries.blob.mimeType", reason: "unsupported"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			record := fixtureFileSetRecord(t)
			test.mutate(entriesOf(record))
			encoded, err := EncodeSnapshot(record)
			assert.Nil(t, encoded)
			requireViolation(t, err, ErrInvalidRecord, test.field, test.reason)
		})
	}

	roleRecord := fixtureFileSetRecord(t)
	entriesOf(roleRecord)[0].Blob.CID = independentCID(t, []byte("wrong file-set role"), cid.DagCBOR)
	roleEncoded, err := EncodeSnapshot(roleRecord)
	assert.Nil(t, roleEncoded)
	requireViolation(t, err, ErrCID, "entries.blob.ref", "role")

	overCap := fixtureFileSetRecord(t)
	overCapEntries := make([]SnapshotEntry, 0, MaxSnapshotEntries+1)
	for index := range MaxSnapshotEntries + 1 {
		name := fmt.Sprintf("file-%03d", index)
		overCapEntries = append(overCapEntries, fixtureEntry(t, name, []byte("canary"), 0o600))
	}
	overCap.Segments[0].Entries = overCapEntries
	overCapEncoded, err := EncodeSnapshot(overCap)
	assert.Nil(t, overCapEncoded)
	requireViolation(t, err, ErrInvalidRecord, "entries", "count")
}

func TestDecodeSnapshotRefusesMalformedFileSetEntries(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
		field  string
		reason string
	}{
		{name: "entries not array", mutate: func(value map[string]any) {
			segmentValue(value, 0)["entries"] = "inline"
		}, field: "entries", reason: "type"},
		{name: "entry not object", mutate: func(value map[string]any) {
			segmentValue(value, 0)["entries"] = []any{"inline"}
		}, field: "entries", reason: "type"},
		{name: "empty entries", mutate: func(value map[string]any) {
			segmentValue(value, 0)["entries"] = []any{}
		}, field: "entries", reason: "empty"},
		{name: "missing entry field", mutate: func(value map[string]any) {
			delete(fileSetEntryValue(t, value, 0), "kind")
		}, field: "record", reason: "fields"},
		{name: "extra entry field", mutate: func(value map[string]any) {
			fileSetEntryValue(t, value, 0)["target"] = "files"
		}, field: "record", reason: "fields"},
		{name: "path type", mutate: func(value map[string]any) {
			fileSetEntryValue(t, value, 0)["path"] = int64(1)
		}, field: "entries.path", reason: "type"},
		{name: "parent segment", mutate: func(value map[string]any) {
			fileSetEntryValue(t, value, 0)["path"] = "lua/../init.lua"
		}, field: "entries.path", reason: "dot_segment"},
		{name: "mode range", mutate: func(value map[string]any) {
			fileSetEntryValue(t, value, 0)["mode"] = int64(0o7777)
		}, field: "entries.mode", reason: "range"},
		{name: "mode unsupported", mutate: func(value map[string]any) {
			fileSetEntryValue(t, value, 0)["mode"] = int64(0o755)
		}, field: "entries.mode", reason: "unsupported"},
		{name: "size range", mutate: func(value map[string]any) {
			fileSetEntryValue(t, value, 0)["size"] = int64(0)
		}, field: "entries.size", reason: "range"},
		{name: "size mismatch", mutate: func(value map[string]any) {
			fileSetEntryValue(t, value, 0)["size"] = int64(4)
		}, field: "entries.size", reason: "mismatch"},
		{name: "kind type", mutate: func(value map[string]any) {
			fileSetEntryValue(t, value, 0)["kind"] = int64(1)
		}, field: "entries.kind", reason: "type"},
		{name: "kind not file", mutate: func(value map[string]any) {
			fileSetEntryValue(t, value, 0)["kind"] = "directory"
		}, field: "entries.kind", reason: "unsupported"},
		{name: "blob not blob", mutate: func(value map[string]any) {
			fileSetEntryValue(t, value, 0)["blob"] = "inline"
		}, field: "entries.blob", reason: "type"},
		{name: "blob media type", mutate: func(value map[string]any) {
			fileSetEntryValue(t, value, 0)["blob"].(map[string]any)["mimeType"] = "image/png"
		}, field: "entries.blob.mimeType", reason: "unsupported"},
		{name: "blob size range", mutate: func(value map[string]any) {
			fileSetEntryValue(t, value, 0)["blob"].(map[string]any)["size"] = int64(0)
		}, field: "entries.blob.size", reason: "range"},
		{name: "duplicate path", mutate: func(value map[string]any) {
			entries := segmentValue(value, 0)["entries"].([]any)
			entries[1].(map[string]any)["path"] = entries[0].(map[string]any)["path"]
		}, field: "entries.path", reason: "duplicate"},
		{name: "unsorted path", mutate: func(value map[string]any) {
			entries := segmentValue(value, 0)["entries"].([]any)
			entries[0].(map[string]any)["path"] = "zzz.lua"
		}, field: "entries.path", reason: "order"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			value := independentFileSetValue(t, fixtureFileSetRecord(t))
			test.mutate(value)
			decoded, err := DecodeSnapshot(testCBOR(value))
			assert.Equal(t, SnapshotRecord{}, decoded)
			requireViolation(t, err, ErrInvalidRecord, test.field, test.reason)
		})
	}
}

func TestFileSetRecordRefusesPackedOnlyConsumers(t *testing.T) {
	packed := fixtureSnapshotValue(t)
	reference, err := packed.PackedPayload()
	require.NoError(t, err)
	assert.Equal(t, blobOf(packed), reference)

	fileSet := fixtureFileSetRecord(t)
	_, err = fileSet.PackedPayload()
	requireViolation(t, err, ErrPackedPayloadRequired, "segments", "packed_only")

	encoded, err := EncodeSnapshot(fileSet)
	require.NoError(t, err)
	payload, err := RecordToJSON(encoded)
	require.NoError(t, err)
	assert.Contains(t, string(payload), `"entries"`)
	assert.NotContains(t, string(payload), `"blobCid"`)
}

func TestFileSetEntriesRefuseUnrepresentableSnapshotContent(t *testing.T) {
	cases := []struct {
		name   string
		entry  model.Entry
		field  string
		reason string
	}{
		{name: "setting entry", entry: model.Entry{
			TargetID: "gnome",
			Setting: &model.SettingEntry{
				SchemaID: "org.gnome.desktop.interface",
				Path:     "/org/gnome/desktop/interface/",
				Key:      "color-scheme",
				State:    model.SettingPresent,
				Value:    &model.VariantValue{Type: "s", Text: "prefer-dark"},
			},
		}, field: "entries.setting", reason: "unsupported"},
		{name: "symlink entry", entry: model.Entry{
			TargetID: "files",
			File: &model.FileEntry{
				Path: "lua/current", State: model.FilePresent, Kind: model.FileSymlink, LinkTarget: "../shared",
			},
		}, field: "entries.symlink", reason: "unsupported"},
		{name: "directory entry", entry: model.Entry{
			TargetID: "files",
			File:     &model.FileEntry{Path: "lua", State: model.FilePresent, Kind: model.FileDirectory},
		}, field: "entries.directory", reason: "unsupported"},
		{name: "deleted file entry", entry: model.Entry{
			TargetID: "files",
			File:     &model.FileEntry{Path: "init.lua", State: model.FileDeleted},
		}, field: "entries.deleted", reason: "unsupported"},
		{name: "empty file entry", entry: model.Entry{
			TargetID: "files",
			File: &model.FileEntry{
				Path: "empty.lua", State: model.FilePresent, Kind: model.FileRegular, Content: []byte{}, Mode: 0o600,
			},
		}, field: "entries.size", reason: "empty"},
		{name: "unsupported mode entry", entry: model.Entry{
			TargetID: "files",
			File: &model.FileEntry{
				Path: "init.lua", State: model.FilePresent, Kind: model.FileRegular,
				Content: []byte("canary"), Mode: 0o755,
			},
		}, field: "entries.mode", reason: "unsupported"},
		{name: "root path entry", entry: model.Entry{
			TargetID: "files",
			File: &model.FileEntry{
				Path: ".", State: model.FilePresent, Kind: model.FileRegular, Content: []byte("canary"), Mode: 0o600,
			},
		}, field: "entries.path", reason: "dot_segment"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			entries, err := SnapshotEntries(model.Snapshot{
				Version: model.SnapshotVersion,
				Entries: []model.Entry{test.entry},
			})
			assert.Nil(t, entries)
			requireViolation(t, err, ErrFileSetEntryUnsupported, test.field, test.reason)
		})
	}

	empty, err := SnapshotEntries(model.Snapshot{Version: model.SnapshotVersion})
	assert.Nil(t, empty)
	requireViolation(t, err, ErrFileSetEntryUnsupported, "entries", "empty")
}

func TestFileSetEntriesNameTheUnrepresentableEntry(t *testing.T) {
	cases := []struct {
		name   string
		entry  model.Entry
		field  string
		reason string
	}{
		{name: "setting entry", entry: model.Entry{
			TargetID: "gnome",
			Setting: &model.SettingEntry{
				SchemaID: "org.gnome.desktop.interface",
				Path:     "/org/gnome/desktop/interface/",
				Key:      "color-scheme",
				State:    model.SettingPresent,
				Value:    &model.VariantValue{Type: "s", Text: "prefer-dark"},
			},
		}, field: "entries.setting", reason: "unsupported"},
		{name: "symlink entry", entry: model.Entry{
			TargetID: "files",
			File: &model.FileEntry{
				Path: "lua/current", State: model.FilePresent, Kind: model.FileSymlink, LinkTarget: "../shared",
			},
		}, field: "entries.symlink", reason: "unsupported"},
		{name: "directory entry", entry: model.Entry{
			TargetID: "files",
			File:     &model.FileEntry{Path: "lua", State: model.FilePresent, Kind: model.FileDirectory},
		}, field: "entries.directory", reason: "unsupported"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			entries, err := SnapshotEntries(model.Snapshot{
				Version: model.SnapshotVersion,
				Entries: []model.Entry{test.entry},
			})
			assert.Nil(t, entries)
			requireViolation(t, err, ErrFileSetEntryUnsupported, test.field, test.reason)
			named, ok := errors.AsType[*FileSetEntryError](err)
			require.True(t, ok, "refusal does not name the entry")
			assert.Equal(t, test.entry.Identity(), named.Entry)
			assert.Equal(t, test.field, named.Field)
			assert.Equal(t, test.reason, named.Reason)
		})
	}
}

func TestFileSetEntriesRefuseAFileSetPastSixtyFourEntries(t *testing.T) {
	assert.Equal(t, 64, MaxSnapshotEntries)
	atBound := make([]model.Entry, 0, MaxSnapshotEntries)
	for index := range MaxSnapshotEntries {
		atBound = append(atBound, model.Entry{TargetID: "files", File: &model.FileEntry{
			Path: fmt.Sprintf("file-%03d.lua", index), State: model.FilePresent, Kind: model.FileRegular,
			Content: []byte("canary"), Mode: 0o600,
		}})
	}
	entries, err := SnapshotEntries(model.Snapshot{Version: model.SnapshotVersion, Entries: atBound})
	require.NoError(t, err)
	assert.Len(t, entries, MaxSnapshotEntries)

	pastBound := append(
		append([]model.Entry{}, atBound...),
		model.Entry{TargetID: "files", File: &model.FileEntry{
			Path: "file-999.lua", State: model.FilePresent, Kind: model.FileRegular,
			Content: []byte("canary"), Mode: 0o600,
		}},
	)
	entries, err = SnapshotEntries(model.Snapshot{Version: model.SnapshotVersion, Entries: pastBound})
	assert.Nil(t, entries)
	requireViolation(t, err, ErrFileSetEntryUnsupported, "entries", "count")
}

func TestFileSetEntriesSortRegularFilesIntoARecord(t *testing.T) {
	entries, err := SnapshotEntries(model.Snapshot{
		Version: model.SnapshotVersion,
		Entries: []model.Entry{
			{TargetID: "files", File: &model.FileEntry{
				Path: "lua/config/options.lua", State: model.FilePresent, Kind: model.FileRegular,
				Content: []byte("options"), Mode: 0o644,
			}},
			{TargetID: "files", File: &model.FileEntry{
				Path: "init.lua", State: model.FilePresent, Kind: model.FileRegular,
				Content: []byte("init"), Mode: 0o600,
			}},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, []SnapshotEntry{
		fixtureEntry(t, "init.lua", []byte("init"), 0o600),
		fixtureEntry(t, "lua/config/options.lua", []byte("options"), 0o644),
	}, entries)

	record := SnapshotRecord{
		SchemaVersion: SchemaVersion,
		Vault:         fixtureVault(),
		PublicationID: fixturePublicationID(),
		Segments: []SnapshotSegment{{
			Target: fixtureFileSetTargets()[0], Form: SegmentFormEntries, Entries: entries,
		}},
	}
	encoded, err := EncodeSnapshot(record)
	require.NoError(t, err)
	decoded, err := DecodeSnapshot(encoded)
	require.NoError(t, err)
	assert.Equal(t, record, decoded)
}

func TestFileSetRecordRefusesPastTheRecordSizeBound(t *testing.T) {
	segments := strings.Repeat("p", MaxEntryPathBytes-4)
	entries := make([]SnapshotEntry, 0, MaxSnapshotEntries)
	for index := range MaxSnapshotEntries {
		entries = append(entries, fixtureEntry(t, fmt.Sprintf("%03d/%s", index, segments), []byte("x"), 0o600))
	}
	record := SnapshotRecord{
		SchemaVersion: SchemaVersion,
		Vault:         fixtureVault(),
		PublicationID: fixturePublicationID(),
		Segments: []SnapshotSegment{{
			Target: fixtureFileSetTargets()[0], Form: SegmentFormEntries, Entries: entries,
		}},
	}
	encoded, err := EncodeSnapshot(record)
	require.NoError(t, err)
	decoded, err := DecodeSnapshot(encoded)
	assert.Equal(t, SnapshotRecord{}, decoded)
	requireViolation(t, err, ErrInvalidRecord, "record", "size_limit")
}

func fixtureFileSetRecord(t testing.TB) SnapshotRecord {
	t.Helper()
	return SnapshotRecord{
		SchemaVersion: SchemaVersion,
		Vault:         fixtureVault(),
		PublicationID: fixturePublicationID(),
		Segments: []SnapshotSegment{{
			Target: fixtureFileSetTargets()[0],
			Form:   SegmentFormEntries,
			Entries: []SnapshotEntry{
				fixtureEntry(t, "init.lua", []byte("file-set init"), 0o600),
				fixtureEntry(t, "lua/config/options.lua", []byte("file-set options"), 0o644),
			},
		}},
	}
}

func fixtureFileSetTargets() []model.Target {
	return []model.Target{{
		ID: "files", Source: model.SourceFiles, SourceVersion: model.SourceVersion,
		Root: &model.FileRoot{Base: model.RootXDGConfig, Path: "dotfiles", Kind: model.SelectionDirectory},
	}}
}

func fixtureEntry(t testing.TB, path string, content []byte, mode uint32) SnapshotEntry {
	t.Helper()
	reference, err := RawPayloadCID(content)
	require.NoError(t, err)
	return SnapshotEntry{
		Path: path,
		Mode: mode,
		Size: uint64(len(content)),
		Kind: SnapshotEntryKindFile,
		Blob: BlobReference{CID: reference, Size: uint64(len(content)), MIMEType: BlobMIMEType},
	}
}

func independentEntriesValue(t testing.TB, entries []SnapshotEntry) []any {
	t.Helper()
	values := make([]any, 0, len(entries))
	for _, entry := range entries {
		reference, err := cid.Cast(entry.Blob.CID)
		require.NoError(t, err)
		values = append(values, map[string]any{
			"path": entry.Path,
			"mode": int64(entry.Mode),
			"size": int64(entry.Size),
			"kind": entry.Kind,
			"blob": map[string]any{
				"$type":    "blob",
				"ref":      testTag{number: 42, value: append([]byte{0}, reference.Bytes()...)},
				"mimeType": entry.Blob.MIMEType,
				"size":     int64(entry.Blob.Size),
			},
		})
	}
	return values
}

func independentFileSetValue(t testing.TB, record SnapshotRecord) map[string]any {
	t.Helper()
	return independentSnapshotValue(t, record)
}

func independentTargetsValue(targets []model.Target) []any {
	values := make([]any, 0, len(targets))
	for _, target := range targets {
		values = append(values, map[string]any{
			"id":             target.ID,
			"source":         string(target.Source),
			"source_version": int64(target.SourceVersion),
			"root": map[string]any{
				"base": string(target.Root.Base),
				"path": target.Root.Path,
				"kind": string(target.Root.Kind),
			},
		})
	}
	return values
}

func independentFileSetBytes(t testing.TB, record SnapshotRecord) []byte {
	t.Helper()
	return testCBOR(independentFileSetValue(t, record))
}

func independentSnapshotValueWithEntries(t testing.TB, packed SnapshotRecord, entries []SnapshotEntry) map[string]any {
	t.Helper()
	value := independentSnapshotValue(t, packed)
	segments, _ := value["segments"].([]any)
	segmentValue, _ := segments[0].(map[string]any)
	segmentValue["entries"] = independentEntriesValue(t, entries)
	return value
}

func fileSetEntryValue(t testing.TB, value map[string]any, index int) map[string]any {
	t.Helper()
	entries, ok := segmentValue(value, 0)["entries"].([]any)
	require.True(t, ok)
	require.Less(t, index, len(entries))
	entry, ok := entries[index].(map[string]any)
	require.True(t, ok)
	return entry
}

func TestSnapshotRecordRefusesAFileTargetWithADifferentEntryPath(t *testing.T) {
	record := fixtureFileSetRecord(t)
	record.Segments[0].Entries = record.Segments[0].Entries[:1]
	record.Segments[0].Target.Root = &model.FileRoot{
		Base: model.RootXDGConfig, Path: "dotfiles/other.lua", Kind: model.SelectionFile,
	}
	encoded, err := EncodeSnapshot(record)
	assert.Nil(t, encoded)
	requireViolation(t, err, ErrInvalidRecord, "segments.target", "mismatch")

	record.Segments[0].Target.Root.Path = "dotfiles/init.lua"
	encoded, err = EncodeSnapshot(record)
	require.NoError(t, err)
	decoded, err := DecodeSnapshot(encoded)
	require.NoError(t, err)
	assert.Equal(t, record, decoded)
}

func TestSnapshotRecordRefusesASegmentWithAnUnsupportedSource(t *testing.T) {
	record := fixtureFileSetRecord(t)
	record.Segments[0].Target.Source = model.SourceGNOME
	record.Segments[0].Target.Root = nil
	encoded, err := EncodeSnapshot(record)
	assert.Nil(t, encoded)
	requireViolation(t, err, ErrInvalidRecord, "segments.form", "entries")
}

func independentSettingsValues(settings []SnapshotSetting) []any {
	values := make([]any, 0, len(settings))
	for _, setting := range settings {
		entry := map[string]any{
			"schemaId": setting.SchemaID, "path": setting.Path, "key": setting.Key,
			"state": string(setting.State),
		}
		if setting.Value != nil {
			entry["value"] = map[string]any{"$type": setting.Value.Type, "text": setting.Value.Text}
		}
		values = append(values, entry)
	}
	return values
}

func segmentValue(value map[string]any, index int) map[string]any {
	segments, ok := value["segments"].([]any)
	if !ok || index >= len(segments) {
		return nil
	}
	segment, _ := segments[index].(map[string]any)
	return segment
}
