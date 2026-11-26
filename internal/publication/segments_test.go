package publication

import (
	"testing"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/model"
)

func roundTripSegment(t *testing.T, segment SnapshotSegment) SnapshotSegment {
	t.Helper()
	value, err := encodeSegment(segment)
	require.NoError(t, err)
	encoded, err := atdata.MarshalCBOR(value)
	require.NoError(t, err)
	parsed, err := atdata.UnmarshalCBOR(encoded)
	require.NoError(t, err)
	decoded, err := decodeSegment(parsed)
	require.NoError(t, err)
	return decoded
}

func fixtureSettingsSegment() SnapshotSegment {
	return SnapshotSegment{
		Target: model.Target{ID: "desktop", Source: model.SourceGNOME, SourceVersion: model.SourceVersion},
		Form:   SegmentFormSettings,
		Settings: []SnapshotSetting{
			{SchemaID: "org.example.A", Path: "/", Key: "alpha", State: model.SettingPresent,
				Value: &model.VariantValue{Type: "b", Text: "true"}},
			{SchemaID: "org.example.A", Path: "/", Key: "beta", State: model.SettingReset},
		},
	}
}

func TestSnapshotSegmentRoundTripsEveryForm(t *testing.T) {
	entries := SnapshotSegment{
		Target:  fixtureFileSetTargets()[0],
		Form:    SegmentFormEntries,
		Entries: []SnapshotEntry{fixtureEntry(t, "init.lua", []byte("init"), 0o600)},
	}
	assert.Equal(t, entries, roundTripSegment(t, entries))

	settings := fixtureSettingsSegment()
	assert.Equal(t, settings, roundTripSegment(t, settings))

	payload := []byte("packed bytes")
	blobCID, err := RawPayloadCID(payload)
	require.NoError(t, err)
	packed := SnapshotSegment{
		Target: fixtureFileSetTargets()[0],
		Form:   SegmentFormPacked,
		Blob: BlobReference{
			CID: blobCID, Size: uint64(len(payload)), MIMEType: SnapshotBlobMIMEType,
		},
	}
	assert.Equal(t, packed, roundTripSegment(t, packed))
}

func TestSnapshotSegmentRefusesMismatchedForms(t *testing.T) {
	gnome := model.Target{ID: "desktop", Source: model.SourceGNOME, SourceVersion: model.SourceVersion}
	_, err := encodeSegment(SnapshotSegment{
		Target:  gnome,
		Form:    SegmentFormEntries,
		Entries: []SnapshotEntry{fixtureEntry(t, "init.lua", []byte("init"), 0o600)},
	})
	requireViolation(t, err, ErrInvalidRecord, "segments.form", "entries")

	_, err = encodeSegment(SnapshotSegment{
		Target:   fixtureFileSetTargets()[0],
		Form:     SegmentFormSettings,
		Settings: fixtureSettingsSegment().Settings,
	})
	requireViolation(t, err, ErrInvalidRecord, "segments.form", "settings")

	_, err = encodeSegment(SnapshotSegment{
		Target:  fixtureFileSetTargets()[0],
		Form:    SegmentFormPacked,
		Entries: []SnapshotEntry{fixtureEntry(t, "init.lua", []byte("init"), 0o600)},
	})
	requireViolation(t, err, ErrInvalidRecord, "segments.form", "packed")
}

func TestSnapshotSegmentRefusesUnorderedSettings(t *testing.T) {
	segment := fixtureSettingsSegment()
	segment.Settings[0], segment.Settings[1] = segment.Settings[1], segment.Settings[0]
	_, err := encodeSegment(segment)
	requireViolation(t, err, ErrInvalidRecord, "segments.settings", "order")

	segment = fixtureSettingsSegment()
	segment.Settings[1] = segment.Settings[0]
	_, err = encodeSegment(segment)
	requireViolation(t, err, ErrInvalidRecord, "segments.settings", "duplicate")
}

func TestSnapshotSegmentRequiresTheFileRootBasename(t *testing.T) {
	segment := SnapshotSegment{
		Target: model.Target{
			ID: "files", Source: model.SourceFiles, SourceVersion: model.SourceVersion,
			Root: &model.FileRoot{Base: model.RootXDGConfig, Path: "dotfiles/other.lua", Kind: model.SelectionFile},
		},
		Form:    SegmentFormEntries,
		Entries: []SnapshotEntry{fixtureEntry(t, "init.lua", []byte("init"), 0o600)},
	}
	_, err := encodeSegment(segment)
	requireViolation(t, err, ErrInvalidRecord, "segments.target", "mismatch")
}

func TestSnapshotSegmentListRequiresUniqueSortedTargets(t *testing.T) {
	first := SnapshotSegment{
		Target:  fixtureFileSetTargets()[0],
		Form:    SegmentFormEntries,
		Entries: []SnapshotEntry{fixtureEntry(t, "init.lua", []byte("init"), 0o600)},
	}
	second := fixtureSettingsSegment()

	require.NoError(t, validateSegmentList([]SnapshotSegment{second, first}))
	_, err := encodeSegments([]SnapshotSegment{second, first})
	require.NoError(t, err)
	requireViolation(t, validateSegmentList([]SnapshotSegment{first, second}), ErrInvalidRecord, "segments.target", "order")

	duplicate := first
	requireViolation(t, validateSegmentList([]SnapshotSegment{first, duplicate}), ErrInvalidRecord, "segments.target", "duplicate")
}

func TestSettingsResetCarriesNoValueProperty(t *testing.T) {
	record := SnapshotRecord{
		SchemaVersion: SchemaVersion, Vault: fixtureVault(), PublicationID: fixturePublicationID(),
		Segments: []SnapshotSegment{{
			Target: model.Target{ID: "desktop", Source: model.SourceGNOME, SourceVersion: model.SourceVersion},
			Form:   SegmentFormSettings,
			Settings: []SnapshotSetting{
				{
					SchemaID: "org.gnome.desktop.interface", Path: "/org/gnome/desktop/interface/",
					Key: "clock-format", State: model.SettingPresent,
					Value: &model.VariantValue{Type: "s", Text: "'24h'"},
				},
				{
					SchemaID: "org.gnome.desktop.interface", Path: "/org/gnome/desktop/interface/",
					Key: "color-scheme", State: model.SettingReset,
				},
			},
		}},
	}
	encoded, err := EncodeSnapshot(record)
	require.NoError(t, err)
	decoded, err := DecodeSnapshot(encoded)
	require.NoError(t, err)
	require.Len(t, decoded.Segments, 1)
	require.Len(t, decoded.Segments[0].Settings, 2)
	require.NotNil(t, decoded.Segments[0].Settings[0].Value)
	assert.Equal(t, "s", decoded.Segments[0].Settings[0].Value.Type)
	assert.Nil(t, decoded.Segments[0].Settings[1].Value)

	object, err := decodeSnapshotObject(encoded)
	require.NoError(t, err)
	segments, ok := object["segments"].([]any)
	require.True(t, ok)
	require.Len(t, segments, 1)
	segment, ok := segments[0].(map[string]any)
	require.True(t, ok)
	settings, ok := segment["settings"].([]any)
	require.True(t, ok)
	require.Len(t, settings, 2)
	present, ok := settings[0].(map[string]any)
	require.True(t, ok)
	assert.Contains(t, present, "value")
	reset, ok := settings[1].(map[string]any)
	require.True(t, ok)
	assert.NotContains(t, reset, "value")
}
