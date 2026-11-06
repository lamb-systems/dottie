package vault

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnpackPayloadReconstructsPlaintextAcrossRegularFiles(t *testing.T) {
	snapshot := model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{fileTarget("files", ".", model.SelectionDirectory)},
		Entries: []model.Entry{
			fileEntry("files", "a", model.FileRegular, model.FilePresent, []byte("first body")),
			fileEntry("files", "b", model.FileRegular, model.FilePresent, []byte("second body has different size")),
		},
	}
	blob, err := Pack(snapshot)
	require.NoError(t, err)
	got, err := UnpackPayload(blob.Payload)
	require.NoError(t, err)
	assert.True(t, equalSnapshots(canonicalSnapshot(snapshot), got))
	assert.Equal(t, []byte("first body"), got.Entries[0].File.Content)
	assert.Equal(t, []byte("second body has different size"), got.Entries[1].File.Content)
}

func TestUnpackPayloadReturnsCompleteSnapshotAndCopiesMemberData(t *testing.T) {
	empty := model.Snapshot{Version: model.SnapshotVersion}
	emptyBlob, err := Pack(empty)
	require.NoError(t, err)
	emptyResult, err := UnpackPayload(emptyBlob.Payload)
	require.NoError(t, err)
	assert.True(t, equalSnapshots(canonicalSnapshot(empty), emptyResult))

	snapshot := payloadTestSnapshot()
	blob, err := Pack(snapshot)
	require.NoError(t, err)
	input := bytes.Clone(blob.Payload)
	got, err := UnpackPayload(input)
	require.NoError(t, err)
	assert.True(t, equalSnapshots(canonicalSnapshot(snapshot), got))

	for index := range input {
		input[index] = 0
	}
	assert.True(t, equalSnapshots(canonicalSnapshot(snapshot), got))
	for _, entry := range got.Entries {
		if entry.File != nil && entry.File.Path == "editor/init.lua" {
			assert.Equal(t, []byte("synthetic editor configuration\n"), entry.File.Content)
		}
	}
}

func TestPayloadLimitsAreLowerOnlyAndDefaultsAreIndependent(t *testing.T) {
	first := DefaultPayloadLimits()
	second := DefaultPayloadLimits()
	assert.Equal(t, int64(402653184), first.MaxPackedBytes)
	assert.Equal(t, DefaultLimits(), first.Snapshot)
	first.MaxPackedBytes = 1
	first.Snapshot = Limits{MaxEntries: -1, MaxDepth: -1, MaxEntryBytes: -1, MaxTotalBytes: -1, MaxManifestBytes: -1, MaxPathBytes: -1}
	assert.Equal(t, DefaultPayloadLimits(), second)

	blob, err := Pack(payloadTestSnapshot())
	require.NoError(t, err)
	limits := DefaultPayloadLimits()
	limits.MaxPackedBytes = int64(len(blob.Payload))
	got, err := UnpackPayloadWithLimits(blob.Payload, limits)
	require.NoError(t, err)
	assert.True(t, equalSnapshots(canonicalSnapshot(payloadTestSnapshot()), got))

	limits.MaxPackedBytes--
	got, err = UnpackPayloadWithLimits(blob.Payload, limits)
	assert.Equal(t, model.Snapshot{}, got)
	assertPayloadError(t, err, "size", "bound", "MaxPackedBytes", ErrPayloadBound)

	limits = DefaultPayloadLimits()
	limits.MaxPackedBytes++
	got, err = UnpackPayloadWithLimits(blob.Payload, limits)
	assert.Equal(t, model.Snapshot{}, got)
	assertPayloadError(t, err, "limits", "invalid", "", ErrPayloadLimits)

	limits = DefaultPayloadLimits()
	limits.Snapshot.MaxEntries++
	got, err = UnpackPayloadWithLimits(blob.Payload, limits)
	assert.Equal(t, model.Snapshot{}, got)
	assertPayloadError(t, err, "limits", "invalid", "", ErrPayloadLimits)

	limits = DefaultPayloadLimits()
	limits.Snapshot.MaxDepth = 0
	zeroDepth := model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{fileTarget("single", "file", model.SelectionFile)},
		Entries: []model.Entry{fileEntry("single", ".", model.FileRegular, model.FilePresent, []byte("x"))},
	}
	zeroDepthBlob, err := Pack(zeroDepth)
	require.NoError(t, err)
	got, err = UnpackPayloadWithLimits(zeroDepthBlob.Payload, limits)
	require.NoError(t, err)
	assert.True(t, equalSnapshots(canonicalSnapshot(zeroDepth), got))

	limits.Snapshot.MaxDepth = -1
	got, err = UnpackPayloadWithLimits(blob.Payload, limits)
	assert.Equal(t, model.Snapshot{}, got)
	assertPayloadError(t, err, "limits", "invalid", "", ErrPayloadLimits)
}

func TestPayloadInvalidLimitsPrecedeMalformedInput(t *testing.T) {
	invalid := []struct {
		name string
		edit func(*PayloadLimits)
	}{
		{"packed-above-default", func(limits *PayloadLimits) { limits.MaxPackedBytes++ }},
		{"entries-above-default", func(limits *PayloadLimits) { limits.Snapshot.MaxEntries++ }},
		{"depth-above-default", func(limits *PayloadLimits) { limits.Snapshot.MaxDepth++ }},
		{"entry-bytes-above-default", func(limits *PayloadLimits) { limits.Snapshot.MaxEntryBytes++ }},
		{"total-bytes-above-default", func(limits *PayloadLimits) { limits.Snapshot.MaxTotalBytes++ }},
		{"manifest-bytes-above-default", func(limits *PayloadLimits) { limits.Snapshot.MaxManifestBytes++ }},
		{"path-bytes-above-default", func(limits *PayloadLimits) { limits.Snapshot.MaxPathBytes++ }},
		{"packed-zero", func(limits *PayloadLimits) { limits.MaxPackedBytes = 0 }},
		{"packed-negative", func(limits *PayloadLimits) { limits.MaxPackedBytes = -1 }},
		{"entries-zero", func(limits *PayloadLimits) { limits.Snapshot.MaxEntries = 0 }},
		{"entries-negative", func(limits *PayloadLimits) { limits.Snapshot.MaxEntries = -1 }},
		{"depth-negative", func(limits *PayloadLimits) { limits.Snapshot.MaxDepth = -1 }},
		{"entry-bytes-zero", func(limits *PayloadLimits) { limits.Snapshot.MaxEntryBytes = 0 }},
		{"entry-bytes-negative", func(limits *PayloadLimits) { limits.Snapshot.MaxEntryBytes = -1 }},
		{"total-bytes-zero", func(limits *PayloadLimits) { limits.Snapshot.MaxTotalBytes = 0 }},
		{"total-bytes-negative", func(limits *PayloadLimits) { limits.Snapshot.MaxTotalBytes = -1 }},
		{"manifest-bytes-zero", func(limits *PayloadLimits) { limits.Snapshot.MaxManifestBytes = 0 }},
		{"manifest-bytes-negative", func(limits *PayloadLimits) { limits.Snapshot.MaxManifestBytes = -1 }},
		{"path-bytes-zero", func(limits *PayloadLimits) { limits.Snapshot.MaxPathBytes = 0 }},
		{"path-bytes-negative", func(limits *PayloadLimits) { limits.Snapshot.MaxPathBytes = -1 }},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			limits := DefaultPayloadLimits()
			test.edit(&limits)
			got, err := UnpackPayloadWithLimits([]byte("malformed payload"), limits)
			assert.Equal(t, model.Snapshot{}, got)
			assertPayloadError(t, err, "limits", "invalid", "", ErrPayloadLimits)
		})
	}
}

func TestPayloadSnapshotLimitsAcceptExactBoundsAndRejectNextValue(t *testing.T) {
	snapshot := payloadBoundSnapshot()
	blob, err := Pack(snapshot)
	require.NoError(t, err)
	manifest := mustReadManifest(t, blob)

	base := DefaultPayloadLimits()
	base.MaxPackedBytes = int64(len(blob.Payload))
	base.Snapshot.MaxEntries = 1
	base.Snapshot.MaxDepth = 2
	base.Snapshot.MaxEntryBytes = 3
	base.Snapshot.MaxTotalBytes = 3
	base.Snapshot.MaxManifestBytes = int64(len(manifest))
	base.Snapshot.MaxPathBytes = 3
	got, err := UnpackPayloadWithLimits(blob.Payload, base)
	require.NoError(t, err)
	assert.True(t, equalSnapshots(canonicalSnapshot(snapshot), got))

	cases := []struct {
		name string
		edit func(*PayloadLimits)
		kind string
	}{
		{"manifest", func(limits *PayloadLimits) { limits.Snapshot.MaxManifestBytes-- }, "MaxManifestBytes"},
		{"depth", func(limits *PayloadLimits) { limits.Snapshot.MaxDepth-- }, "MaxDepth"},
		{"entry-bytes", func(limits *PayloadLimits) { limits.Snapshot.MaxEntryBytes-- }, "MaxEntryBytes"},
		{"total-bytes", func(limits *PayloadLimits) { limits.Snapshot.MaxTotalBytes-- }, "MaxTotalBytes"},
		{"path-bytes", func(limits *PayloadLimits) { limits.Snapshot.MaxPathBytes-- }, "MaxPathBytes"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			limits := base
			test.edit(&limits)
			got, err := UnpackPayloadWithLimits(blob.Payload, limits)
			assert.Equal(t, model.Snapshot{}, got)
			assertPayloadError(t, err, "inspect", "bound", test.kind, ErrPayloadBound)
		})
	}

	twoEntries := snapshot
	twoEntries.Entries = append(twoEntries.Entries, fileEntry("files", "other", model.FileRegular, model.FilePresent, []byte{}))
	twoBlob, err := Pack(twoEntries)
	require.NoError(t, err)
	limits := DefaultPayloadLimits()
	limits.Snapshot.MaxEntries = 1
	got, err = UnpackPayloadWithLimits(twoBlob.Payload, limits)
	assert.Equal(t, model.Snapshot{}, got)
	assertPayloadError(t, err, "inspect", "bound", "MaxEntries", ErrPayloadBound)
}

func TestPayloadDeclaredAggregateBoundsAllMembers(t *testing.T) {
	manifest, err := encodeManifest(wireManifest{
		Version: Version, Codec: CodecNone, SnapshotVersion: model.SnapshotVersion,
		Targets: []model.Target{},
		Entries: []wireEntry{
			{TargetID: "files", Source: model.SourceFiles, Path: "a", State: string(model.FilePresent), Kind: model.FileRegular, Size: 2, SHA256: strings.Repeat("0", 64), Member: ordinal(1)},
			{TargetID: "files", Source: model.SourceFiles, Path: "b", State: string(model.FileDeleted), Size: 2, SHA256: strings.Repeat("0", 64), Member: ordinal(2)},
		},
	})
	require.NoError(t, err)
	payload := payloadArchive(t, manifest)
	limits := DefaultPayloadLimits()
	limits.Snapshot.MaxEntryBytes = 3
	limits.Snapshot.MaxTotalBytes = 3
	got, err := UnpackPayloadWithLimits(payload, limits)
	assert.Equal(t, model.Snapshot{}, got)
	assertPayloadError(t, err, "inspect", "bound", "MaxTotalBytes", ErrPayloadBound)
}

func TestPayloadStreamingEntryCountStopsBeforeTypedArrayAccumulation(t *testing.T) {
	limits := DefaultPayloadLimits()
	limits.Snapshot.MaxEntries = 1
	for _, entries := range []string{"[{},{}]", "[null,null]", "[{},x", "[null,x"} {
		t.Run(entries, func(t *testing.T) {
			payload := payloadArchive(t, payloadManifestJSON(entries))
			got, err := UnpackPayloadWithLimits(payload, limits)
			assert.Equal(t, model.Snapshot{}, got)
			assertPayloadError(t, err, "inspect", "bound", "MaxEntries", ErrPayloadBound)
		})
	}
}

func TestPayloadStreamingRejectsRepeatedFieldsAndInvalidTargetsEarly(t *testing.T) {
	t.Run("null top-level arrays", func(t *testing.T) {
		payload := payloadArchive(t, []byte(`{"version":1,"codec":"none","snapshot_version":1,"targets":null,"entries":null}`))
		got, err := UnpackPayload(payload)
		require.NoError(t, err)
		assert.True(t, equalSnapshots(model.Snapshot{Version: model.SnapshotVersion}, got))
	})
	t.Run("repeated entries", func(t *testing.T) {
		payload := payloadArchive(t, []byte(`{"version":1,"codec":"none","snapshot_version":1,"targets":[],"entries":[],"entries":[{},{}]}`))
		got, err := UnpackPayload(payload)
		assert.Equal(t, model.Snapshot{}, got)
		assertPayloadError(t, err, "inspect", "malformed", "", ErrInvalidPayload)
	})
	t.Run("repeated empty targets", func(t *testing.T) {
		payload := payloadArchive(t, []byte(`{"version":1,"codec":"none","snapshot_version":1,"targets":[],"targets":[],"entries":[]}`))
		got, err := UnpackPayload(payload)
		assert.Equal(t, model.Snapshot{}, got)
		assertPayloadError(t, err, "inspect", "malformed", "", ErrInvalidPayload)
	})
	t.Run("empty target", func(t *testing.T) {
		payload := payloadArchive(t, []byte(`{"version":1,"codec":"none","snapshot_version":1,"targets":[{}],"entries":[]}`))
		got, err := UnpackPayload(payload)
		assert.Equal(t, model.Snapshot{}, got)
		assertPayloadError(t, err, "inspect", "malformed", "", ErrInvalidPayload)
	})
	t.Run("first target path bound before invalid next JSON", func(t *testing.T) {
		payload := payloadArchive(t, []byte(`{"version":1,"codec":"none","snapshot_version":1,"targets":[{"id":"files","source":"files","source_version":1,"root":{"base":"home","path":"ab","kind":"directory"}},x`))
		limits := DefaultPayloadLimits()
		limits.Snapshot.MaxPathBytes = 1
		got, err := UnpackPayloadWithLimits(payload, limits)
		assert.Equal(t, model.Snapshot{}, got)
		assertPayloadError(t, err, "inspect", "bound", "MaxPathBytes", ErrPayloadBound)
	})
	t.Run("null target before unreadable later JSON", func(t *testing.T) {
		payload := payloadArchive(t, []byte(`{"version":1,"codec":"none","snapshot_version":1,"targets":[null,`))
		got, err := UnpackPayload(payload)
		assert.Equal(t, model.Snapshot{}, got)
		assertPayloadError(t, err, "inspect", "malformed", "", ErrInvalidPayload)
	})
	t.Run("targets must be ascending", func(t *testing.T) {
		payload := payloadArchive(t, []byte(`{"version":1,"codec":"none","snapshot_version":1,"targets":[{"id":"z","source":"gnome","source_version":1},{"id":"a","source":"gnome","source_version":1}],"entries":[]}`))
		got, err := UnpackPayload(payload)
		assert.Equal(t, model.Snapshot{}, got)
		assertPayloadError(t, err, "inspect", "malformed", "", ErrInvalidPayload)
	})
}

func TestPayloadErrorVocabularyAndSafeRedaction(t *testing.T) {
	got, err := UnpackPayload(nil)
	assert.Equal(t, model.Snapshot{}, got)
	assertPayloadError(t, err, "size", "invalid", "", ErrInvalidPayload)

	marker := "private/path-value-canary"
	manifest := []byte(fmt.Sprintf(`{"version":1,"codec":"none","snapshot_version":1,"targets":[],"entries":[{"target_id":"files","source":"files","path":%q,"state":"present","kind":"regular","size":0,"sha256":"%s","member":"000001"}]}`, strings.Repeat("x", model.MaxRelativePathBytes+1)+marker, strings.Repeat("0", 64)))
	payload := payloadArchive(t, manifest)
	limits := DefaultPayloadLimits()
	require.Contains(t, string(payload), marker)
	got, err = UnpackPayloadWithLimits(payload, limits)
	assert.Equal(t, model.Snapshot{}, got)
	assertPayloadError(t, err, "inspect", "bound", "MaxPathBytes", ErrPayloadBound)
	assertPayloadRedacted(t, err, ErrPayloadBound, marker)

	valid, err := Pack(model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{fileTarget("files", ".", model.SelectionDirectory)},
		Entries: []model.Entry{fileEntry("files", marker, model.FileRegular, model.FilePresent, []byte("secret"))},
	})
	require.NoError(t, err)
	changed := rewriteManifest(t, valid, func(manifest *wireManifest) {
		manifest.Entries[0].SHA256 = strings.Repeat("0", 64)
	})
	got, err = UnpackPayload(changed.Payload)
	assert.Equal(t, model.Snapshot{}, got)
	assertPayloadError(t, err, "validate", "malformed", "", ErrInvalidPayload)
	assertPayloadRedacted(t, err, ErrInvalidPayload, marker)

	unknownField := "private_unknown_field_canary"
	unknownValue := "private_unknown_value_canary"
	members := readMembers(t, valid.Payload)
	members[0].data = bytes.Replace(members[0].data, []byte(`"member":"000001"`), []byte(fmt.Sprintf(`%q:%q,"member":"000001"`, unknownField, unknownValue)), 1)
	unknownFieldPayload := encodeMembers(t, members)
	require.Contains(t, string(unknownFieldPayload), unknownField)
	require.Contains(t, string(unknownFieldPayload), unknownValue)
	got, err = UnpackPayload(unknownFieldPayload)
	assert.Equal(t, model.Snapshot{}, got)
	assertPayloadError(t, err, "validate", "malformed", "", ErrInvalidPayload)
	assertPayloadRedacted(t, err, ErrInvalidPayload, unknownField, unknownValue)
}

func TestPayloadInvalidModelAndCanonicalManifestRefusals(t *testing.T) {
	blob, err := Pack(model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{fileTarget("files", ".", model.SelectionDirectory)},
		Entries: []model.Entry{fileEntry("files", "a", model.FileRegular, model.FilePresent, []byte("x"))},
	})
	require.NoError(t, err)

	for _, test := range []struct {
		name   string
		mutate func(*wireManifest)
	}{
		{"invalid path", func(manifest *wireManifest) { manifest.Entries[0].Path = "../unsafe" }},
		{"invalid source", func(manifest *wireManifest) { manifest.Entries[0].Source = "unknown-source" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := rewriteManifest(t, blob, test.mutate)
			got, err := UnpackPayload(changed.Payload)
			assert.Equal(t, model.Snapshot{}, got)
			assertPayloadError(t, err, "validate", "malformed", "", ErrInvalidPayload)
		})
	}

	duplicateSource, err := Pack(model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{fileTarget("files", ".", model.SelectionDirectory)},
		Entries: []model.Entry{
			fileEntry("files", "a", model.FileRegular, model.FilePresent, []byte("a")),
			fileEntry("files", "b", model.FileRegular, model.FilePresent, []byte("b")),
		},
	})
	require.NoError(t, err)
	duplicate := rewriteManifest(t, duplicateSource, func(manifest *wireManifest) { manifest.Entries[1].Path = "a" })
	got, err := UnpackPayload(duplicate.Payload)
	assert.Equal(t, model.Snapshot{}, got)
	assertPayloadError(t, err, "validate", "malformed", "", ErrInvalidPayload)

	settings, err := Pack(model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{{ID: "settings", Source: model.SourceGNOME, SourceVersion: model.SourceVersion}},
		Entries: []model.Entry{{TargetID: "settings", Setting: &model.SettingEntry{SchemaID: "org.example.Desktop", Path: "/org/example/", Key: "theme", State: model.SettingPresent, Value: &model.VariantValue{Type: "s", Text: "'dark'"}}}},
	})
	require.NoError(t, err)
	badSetting := rewriteManifest(t, settings, func(manifest *wireManifest) { manifest.Entries[0].Value = &model.VariantValue{Text: "private-value"} })
	got, err = UnpackPayload(badSetting.Payload)
	assert.Equal(t, model.Snapshot{}, got)
	assertPayloadError(t, err, "validate", "malformed", "", ErrInvalidPayload)
}

func TestPayloadInspectAndValidateFailureStages(t *testing.T) {
	cases := []struct {
		name     string
		input    []byte
		stage    string
		reason   string
		kind     string
		sentinel error
	}{
		{name: "short framing", input: []byte("short"), stage: "inspect", reason: "malformed", sentinel: ErrInvalidPayload},
		{name: "invalid JSON", input: payloadArchive(t, []byte("{")), stage: "inspect", reason: "malformed", sentinel: ErrInvalidPayload},
		{name: "unsupported version", input: payloadArchive(t, []byte(`{"version":2,"codec":"none","snapshot_version":1,"targets":[],"entries":[]}`)), stage: "inspect", reason: "unsupported_profile", sentinel: ErrInvalidPayload},
		{name: "unsupported codec", input: payloadArchive(t, []byte(`{"version":1,"codec":"gzip","snapshot_version":1,"targets":[],"entries":[]}`)), stage: "inspect", reason: "unsupported_profile", sentinel: ErrInvalidPayload},
		{name: "unsupported snapshot version", input: payloadArchive(t, []byte(`{"version":1,"codec":"none","snapshot_version":2,"targets":[],"entries":[]}`)), stage: "inspect", reason: "unsupported_profile", sentinel: ErrInvalidPayload},
		{name: "duplicate field", input: payloadArchive(t, []byte(`{"version":1,"version":1,"codec":"none","snapshot_version":1,"targets":[],"entries":[]}`)), stage: "inspect", reason: "malformed", sentinel: ErrInvalidPayload},
		{name: "unknown field", input: payloadArchive(t, []byte(`{"version":1,"codec":"none","snapshot_version":1,"targets":[],"entries":[],"unsafe":"canary"}`)), stage: "inspect", reason: "malformed", sentinel: ErrInvalidPayload},
		{name: "truncated manifest body", input: payloadTruncatedManifest(t), stage: "inspect", reason: "malformed", sentinel: ErrInvalidPayload},
		{name: "noncanonical JSON", input: payloadArchive(t, []byte("{ \"version\":1,\"codec\":\"none\",\"snapshot_version\":1,\"targets\":[],\"entries\":[]}")), stage: "validate", reason: "malformed", sentinel: ErrInvalidPayload},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got, err := UnpackPayload(test.input)
			assert.Equal(t, model.Snapshot{}, got)
			assertPayloadError(t, err, test.stage, test.reason, test.kind, test.sentinel)
		})
	}
}

func TestPayloadStrictValidationRemainsMandatory(t *testing.T) {
	blob, err := Pack(payloadTestSnapshot())
	require.NoError(t, err)
	badOrdinal := rewriteManifest(t, blob, func(manifest *wireManifest) { manifest.Entries[0].Member = "000099" })
	got, err := UnpackPayload(badOrdinal.Payload)
	assert.Equal(t, model.Snapshot{}, got)
	assertPayloadError(t, err, "validate", "malformed", "", ErrInvalidPayload)

	members := readMembers(t, blob.Payload)
	members[1].header.Name = "000099"
	changed := cloneBlob(blob)
	changed.Payload = encodeMembers(t, members)
	changed.Digest = sha256.Sum256(changed.Payload)
	got, err = UnpackPayload(changed.Payload)
	assert.Equal(t, model.Snapshot{}, got)
	assertPayloadError(t, err, "validate", "malformed", "", ErrInvalidPayload)

	members = readMembers(t, blob.Payload)
	members[1].header.Mode = 0o644
	changed.Payload = encodeMembers(t, members)
	changed.Digest = sha256.Sum256(changed.Payload)
	got, err = UnpackPayload(changed.Payload)
	assert.Equal(t, model.Snapshot{}, got)
	assertPayloadError(t, err, "validate", "malformed", "", ErrInvalidPayload)

	truncated := bytes.Clone(blob.Payload[:len(blob.Payload)-512])
	got, err = UnpackPayload(truncated)
	assert.Equal(t, model.Snapshot{}, got)
	assertPayloadError(t, err, "validate", "malformed", "", ErrInvalidPayload)

	trailing := append(bytes.Clone(blob.Payload), 0x7f)
	got, err = UnpackPayload(trailing)
	assert.Equal(t, model.Snapshot{}, got)
	assertPayloadError(t, err, "validate", "malformed", "", ErrInvalidPayload)

	members = readMembers(t, blob.Payload)
	members[1].header.Typeflag = tar.TypeSymlink
	members[1].header.Linkname = "unsafe"
	changed.Payload = encodeMembers(t, members)
	got, err = UnpackPayload(changed.Payload)
	assert.Equal(t, model.Snapshot{}, got)
	assertPayloadError(t, err, "validate", "malformed", "", ErrInvalidPayload)

	members = readMembers(t, blob.Payload)
	members[1].header.Format = tar.FormatGNU
	changed.Payload = encodeMembers(t, members)
	got, err = UnpackPayload(changed.Payload)
	assert.Equal(t, model.Snapshot{}, got)
	assertPayloadError(t, err, "validate", "malformed", "", ErrInvalidPayload)

	members = readMembers(t, blob.Payload)
	members[1].header.Typeflag = tar.TypeGNUSparse
	changed.Payload = encodeMembers(t, members)
	got, err = UnpackPayload(changed.Payload)
	assert.Equal(t, model.Snapshot{}, got)
	assertPayloadError(t, err, "validate", "malformed", "", ErrInvalidPayload)

	paxPayload := prependPAX(t, blob)
	got, err = UnpackPayload(paxPayload.Payload)
	assert.Equal(t, model.Snapshot{}, got)
	assertPayloadError(t, err, "inspect", "malformed", "", ErrInvalidPayload)

	members = readMembers(t, blob.Payload)
	members = append(members, testMember{header: tar.Header{Name: ordinal(len(members)), Mode: 0o600, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}})
	changed.Payload = encodeMembers(t, members)
	got, err = UnpackPayload(changed.Payload)
	assert.Equal(t, model.Snapshot{}, got)
	assertPayloadError(t, err, "validate", "malformed", "", ErrInvalidPayload)
}

func TestPayloadManifestAndPackedBoundsPrecedeBodyParsing(t *testing.T) {
	blob, err := Pack(payloadTestSnapshot())
	require.NoError(t, err)
	manifestLimit := int64(len(mustReadManifest(t, blob))) - 1
	limits := DefaultPayloadLimits()
	limits.Snapshot.MaxManifestBytes = manifestLimit
	got, err := UnpackPayloadWithLimits(blob.Payload, limits)
	assert.Equal(t, model.Snapshot{}, got)
	assertPayloadError(t, err, "inspect", "bound", "MaxManifestBytes", ErrPayloadBound)

	oversizedHeader := payloadWithManifestSize(t, mustReadManifest(t, blob), DefaultLimits().MaxManifestBytes+1)
	got, err = UnpackPayload(oversizedHeader)
	assert.Equal(t, model.Snapshot{}, got)
	assertPayloadError(t, err, "inspect", "bound", "MaxManifestBytes", ErrPayloadBound)

	largeEntryManifest := []byte(fmt.Sprintf(`{"version":1,"codec":"none","snapshot_version":1,"targets":[],"entries":[{"target_id":"files","source":"files","path":"tiny","state":"present","kind":"regular","size":%d,"sha256":"%s","member":"000001"}]}`, DefaultLimits().MaxEntryBytes+1, strings.Repeat("0", 64)))
	got, err = UnpackPayload(payloadArchive(t, largeEntryManifest))
	assert.Equal(t, model.Snapshot{}, got)
	assertPayloadError(t, err, "inspect", "bound", "MaxEntryBytes", ErrPayloadBound)
}

func FuzzUnpackPayload(f *testing.F) {
	empty, err := Pack(model.Snapshot{Version: model.SnapshotVersion})
	require.NoError(f, err)
	valid, err := Pack(payloadTestSnapshot())
	require.NoError(f, err)
	f.Add(bytes.Clone(empty.Payload))
	f.Add(bytes.Clone(valid.Payload))
	f.Add([]byte("not a tar payload"))
	limits := DefaultPayloadLimits()
	limits.MaxPackedBytes = 64 * 1024
	limits.Snapshot.MaxEntries = 8
	limits.Snapshot.MaxDepth = 8
	limits.Snapshot.MaxEntryBytes = 4096
	limits.Snapshot.MaxTotalBytes = 8192
	limits.Snapshot.MaxManifestBytes = 32 * 1024
	limits.Snapshot.MaxPathBytes = 256
	f.Fuzz(func(t *testing.T, payload []byte) {
		got, err := UnpackPayloadWithLimits(payload, limits)
		if err != nil {
			require.Equal(t, model.Snapshot{}, got)
			return
		}
		require.NoError(t, got.Validate())
		packed, err := Pack(got)
		require.NoError(t, err)
		roundTrip, err := Unpack(packed)
		require.NoError(t, err)
		assert.True(t, equalSnapshots(got, roundTrip))
	})
}

func payloadTestSnapshot() model.Snapshot {
	files := fileTarget("files", "config", model.SelectionDirectory)
	settings := model.Target{ID: "settings", Source: model.SourceGNOME, SourceVersion: model.SourceVersion}
	return model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{files, settings},
		Entries: []model.Entry{
			fileEntry("files", "editor", model.FileDirectory, model.FilePresent, nil),
			{TargetID: "files", File: &model.FileEntry{Path: "editor/init.lua", State: model.FilePresent, Kind: model.FileRegular, Content: []byte("synthetic editor configuration\n"), Mode: 0o600}},
			{TargetID: "files", File: &model.FileEntry{Path: "editor/link", State: model.FilePresent, Kind: model.FileSymlink, LinkTarget: "../shared"}},
			fileEntry("files", "old.conf", "", model.FileDeleted, nil),
			{TargetID: "settings", Setting: &model.SettingEntry{SchemaID: "org.example.Desktop", Path: "/org/example/", Key: "theme", State: model.SettingPresent, Value: &model.VariantValue{Type: "s", Text: "'dark'"}}},
			{TargetID: "settings", Setting: &model.SettingEntry{SchemaID: "org.example.Desktop", Path: "/org/example/", Key: "enabled", State: model.SettingReset}},
		},
	}
}

func payloadBoundSnapshot() model.Snapshot {
	return model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{fileTarget("files", ".", model.SelectionDirectory)},
		Entries: []model.Entry{fileEntry("files", "a/b", model.FileRegular, model.FilePresent, []byte("abc"))},
	}
}

func payloadTruncatedManifest(t *testing.T) []byte {
	t.Helper()
	manifest := []byte(`{"version":1,"codec":"none","snapshot_version":1,"targets":[],"entries":[]}`)
	payload := payloadArchive(t, manifest)
	return bytes.Clone(payload[:512+len(manifest)-1])
}

func payloadManifestJSON(entries string) []byte {
	return []byte(fmt.Sprintf(`{"version":1,"codec":"none","snapshot_version":1,"targets":[],"entries":%s}`, entries))
}

func payloadArchive(t *testing.T, manifest []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	require.NoError(t, writeMember(writer, manifestMember, manifest))
	require.NoError(t, writer.Close())
	return bytes.Clone(buffer.Bytes())
}

func payloadWithManifestSize(t *testing.T, manifest []byte, size int64) []byte {
	t.Helper()
	payload := payloadArchive(t, manifest)
	copy(payload[124:136], []byte(fmt.Sprintf("%011o\x00", size)))
	for index := 148; index < 156; index++ {
		payload[index] = ' '
	}
	var checksum int64
	for _, value := range payload[:512] {
		checksum += int64(value)
	}
	copy(payload[148:156], []byte(fmt.Sprintf("%06o\x00 ", checksum)))
	return payload
}

func assertPayloadError(t *testing.T, err error, stage, reason, kind string, sentinel error) {
	t.Helper()
	require.Error(t, err)
	var payloadErr *PayloadError
	require.ErrorAs(t, err, &payloadErr)
	assert.Equal(t, stage, payloadErr.Stage)
	assert.Equal(t, reason, payloadErr.Reason)
	assert.Equal(t, kind, payloadErr.Kind)
	require.ErrorIs(t, err, sentinel)
}

func assertPayloadRedacted(t *testing.T, err, sentinel error, markers ...string) {
	t.Helper()
	var leaves []error
	var visit func(error)
	visit = func(node error) {
		require.Error(t, node)
		for _, formatted := range []string{fmt.Sprint(node), fmt.Sprintf("%+v", node), fmt.Sprintf("%#v", node)} {
			for _, marker := range markers {
				assert.NotContains(t, formatted, marker)
			}
		}
		if multi, ok := node.(interface{ Unwrap() []error }); ok {
			causes := multi.Unwrap()
			require.NotEmpty(t, causes)
			for _, cause := range causes {
				visit(cause)
			}
			return
		}
		if single, ok := node.(interface{ Unwrap() error }); ok {
			if cause := single.Unwrap(); cause != nil {
				visit(cause)
				return
			}
		}
		leaves = append(leaves, node)
	}
	visit(err)
	assert.Equal(t, []error{sentinel}, leaves)
}
