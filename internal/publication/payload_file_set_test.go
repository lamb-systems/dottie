package publication

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/vault"
)

var errPayloadFetchMissing = errors.New("payload fetch refused")

type payloadFetchCall struct {
	reference BlobReference
}

type payloadFetchMap struct {
	blobs   map[string][]byte
	fails   map[string]error
	fetched []payloadFetchCall
}

func newPayloadFetchMap() *payloadFetchMap {
	return &payloadFetchMap{blobs: map[string][]byte{}, fails: map[string]error{}}
}

func (source *payloadFetchMap) serveFileSet(record SnapshotRecord, contents map[string][]byte) {
	for _, entry := range entriesOf(record) {
		source.blobs[string(entry.Blob.CID)] = bytes.Clone(contents[entry.Path])
	}
}

func (source *payloadFetchMap) fetch(reference BlobReference) ([]byte, error) {
	source.fetched = append(source.fetched, payloadFetchCall{reference: reference})
	if err, found := source.fails[string(reference.CID)]; found {
		return nil, err
	}
	content, found := source.blobs[string(reference.CID)]
	if !found {
		return nil, errPayloadFetchMissing
	}
	return bytes.Clone(content), nil
}

func payloadLimits() PayloadLimits {
	return PayloadLimits{MaxEntries: 512, MaxEntryBytes: 8 << 20, MaxTotalBytes: 64 << 20}
}

type fileSetFile struct {
	path    string
	mode    uint32
	content []byte
}

func newFileSetPayloadFixture(t *testing.T, files ...fileSetFile) (SnapshotRecord, map[string][]byte) {
	t.Helper()
	sorted := slices.Clone(files)
	slices.SortFunc(sorted, func(left, right fileSetFile) int {
		return strings.Compare(left.path, right.path)
	})
	entries := make([]SnapshotEntry, 0, len(sorted))
	contents := make(map[string][]byte, len(sorted))
	for _, file := range sorted {
		entries = append(entries, fixtureEntry(t, file.path, file.content, file.mode))
		contents[file.path] = file.content
	}
	record := SnapshotRecord{
		SchemaVersion: SchemaVersion, Vault: fixtureVault(), PublicationID: fixturePublicationID(),
		Segments: []SnapshotSegment{{
			Target: fixtureFileSetTargets()[0], Form: SegmentFormEntries, Entries: entries,
		}},
	}
	return record, contents
}

func defaultFileSetPayloadFixture(t *testing.T) (SnapshotRecord, map[string][]byte) {
	t.Helper()
	return newFileSetPayloadFixture(
		t,
		fileSetFile{path: "init.lua", mode: 0o600, content: []byte("file-set init")},
		fileSetFile{path: "lua/config/options.lua", mode: 0o644, content: []byte("file-set options")},
	)
}

func TestResolvePayloadReadsPackedThroughTheBlobReference(t *testing.T) {
	snapshot := model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{{
			ID: "files", Source: model.SourceFiles, SourceVersion: model.SourceVersion,
			Root: &model.FileRoot{Base: model.RootHome, Path: "config", Kind: model.SelectionDirectory},
		}},
		Entries: []model.Entry{{
			TargetID: "files",
			File: &model.FileEntry{
				Path: "init.lua", State: model.FilePresent, Kind: model.FileRegular,
				Content: []byte("synthetic packed payload"), Mode: 0o600,
			},
		}},
	}
	packed, err := vault.Pack(snapshot)
	require.NoError(t, err)
	record := fixtureSnapshotValue(t)
	record.Segments[0].Target = snapshot.Targets[0]
	record.Segments[0].Blob = BlobReference{
		CID: mustPayloadRawCID(t, packed.Payload), Size: uint64(len(packed.Payload)),
		MIMEType: SnapshotBlobMIMEType,
	}
	source := newPayloadFetchMap()
	source.blobs[string(blobOf(record).CID)] = bytes.Clone(packed.Payload)

	payload, err := ResolvePayload(record, payloadLimits(), source.fetch)
	require.NoError(t, err)
	assert.Equal(t, PayloadFormPacked, payload.Form)
	assert.Equal(t, snapshot, payload.Snapshot)
	assert.Empty(t, payload.Entries)
	require.Len(t, source.fetched, 1)
	assert.Equal(t, blobOf(record), source.fetched[0].reference)

	resolved, err := payload.PackedSnapshot()
	require.NoError(t, err)
	assert.Equal(t, snapshot, resolved)
}

func TestResolvePayloadReadsFileSetEntriesWithPathsModesAndSizes(t *testing.T) {
	record, contents := defaultFileSetPayloadFixture(t)
	source := newPayloadFetchMap()
	source.serveFileSet(record, contents)

	payload, err := ResolvePayload(record, payloadLimits(), source.fetch)
	require.NoError(t, err)
	assert.Equal(t, PayloadFormFileSet, payload.Form)
	require.Len(t, payload.Snapshot.Targets, 1)
	require.Len(t, payload.Snapshot.Entries, len(entriesOf(record))+2)
	projected := map[string]*model.FileEntry{}
	directories := map[string]bool{}
	for _, entry := range payload.Snapshot.Entries {
		require.NotNil(t, entry.File)
		projected[entry.File.Path] = entry.File
		if entry.File.Kind == model.FileDirectory {
			directories[entry.File.Path] = true
		}
	}
	for _, entry := range entriesOf(record) {
		file := projected[entry.Path]
		require.NotNil(t, file)
		assert.Equal(t, model.FileRegular, file.Kind)
		assert.Equal(t, entry.Mode, file.Mode)
		assert.Equal(t, contents[entry.Path], file.Content)
	}
	assert.Equal(t, map[string]bool{"lua": true, "lua/config": true}, directories)
	require.Len(t, payload.Entries, len(entriesOf(record)))
	for index, entry := range entriesOf(record) {
		assert.Equal(t, entry.Path, payload.Entries[index].Path)
		assert.Equal(t, entry.Mode, payload.Entries[index].Mode)
		assert.Equal(t, entry.Size, payload.Entries[index].Size)
		assert.Equal(t, contents[entry.Path], payload.Entries[index].Content)
		assert.Equal(t, entry.Blob, source.fetched[index].reference)
	}

	snapshot, err := payload.PackedSnapshot()
	assert.Equal(t, model.Snapshot{}, snapshot)
	require.ErrorIs(t, err, ErrFileSetPayload)
}

func TestResolvePayloadRefusesAMissingFileSetEntryNamingThePath(t *testing.T) {
	record, contents := defaultFileSetPayloadFixture(t)
	missing := entriesOf(record)[1]
	source := newPayloadFetchMap()
	source.blobs[string(entriesOf(record)[0].Blob.CID)] = contents[entriesOf(record)[0].Path]
	source.fails[string(missing.Blob.CID)] = errPayloadFetchMissing

	payload, err := ResolvePayload(record, payloadLimits(), source.fetch)
	assert.Equal(t, Payload{}, payload)
	require.ErrorIs(t, err, ErrFileSetPayload)
	require.ErrorIs(t, err, errPayloadFetchMissing)
	var refusal *FileSetPayloadError
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, missing.Path, refusal.EntryPath())
	assert.Equal(t, FileSetReasonUnavailable, refusal.Reason)
	assert.Contains(t, err.Error(), missing.Path)
	require.Len(t, source.fetched, 2)
}

func TestResolvePayloadRefusesAFileSetEntrySizeMismatchNamingTheEntry(t *testing.T) {
	record, contents := defaultFileSetPayloadFixture(t)
	mismatched := entriesOf(record)[1]
	short := bytes.Clone(contents[mismatched.Path])
	short = short[:len(short)-1]
	source := newPayloadFetchMap()
	source.blobs[string(entriesOf(record)[0].Blob.CID)] = contents[entriesOf(record)[0].Path]
	source.blobs[string(mismatched.Blob.CID)] = short

	payload, err := ResolvePayload(record, payloadLimits(), source.fetch)
	assert.Equal(t, Payload{}, payload)
	require.ErrorIs(t, err, ErrFileSetPayload)
	require.ErrorIs(t, err, ErrPayload)
	var refusal *FileSetPayloadError
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, mismatched.Path, refusal.EntryPath())
	assert.Equal(t, FileSetReasonMismatch, refusal.Reason)
	var violationErr *ViolationError
	require.ErrorAs(t, err, &violationErr)
	assert.Equal(t, "blob.size", violationErr.Field())
	assert.Equal(t, "mismatch", violationErr.Reason())
}

func TestResolvePayloadRefusesAFileSetEntryCIDMismatchNamingTheEntry(t *testing.T) {
	record, contents := defaultFileSetPayloadFixture(t)
	mismatched := entriesOf(record)[1]
	substitute := bytes.Clone(contents[mismatched.Path])
	substitute[0] ^= 0xff
	source := newPayloadFetchMap()
	source.blobs[string(entriesOf(record)[0].Blob.CID)] = contents[entriesOf(record)[0].Path]
	source.blobs[string(mismatched.Blob.CID)] = substitute

	payload, err := ResolvePayload(record, payloadLimits(), source.fetch)
	assert.Equal(t, Payload{}, payload)
	require.ErrorIs(t, err, ErrFileSetPayload)
	var refusal *FileSetPayloadError
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, mismatched.Path, refusal.EntryPath())
	assert.Equal(t, FileSetReasonMismatch, refusal.Reason)
	var violationErr *ViolationError
	require.ErrorAs(t, err, &violationErr)
	assert.Equal(t, "blob.ref", violationErr.Field())
}

func TestResolvePayloadRefusesFileSetPayloadsBeyondItsBounds(t *testing.T) {
	record, contents := defaultFileSetPayloadFixture(t)
	source := newPayloadFetchMap()
	source.serveFileSet(record, contents)
	var refusal *FileSetPayloadError

	payload, err := ResolvePayload(record, PayloadLimits{MaxEntries: 1}, source.fetch)
	assert.Equal(t, Payload{}, payload)
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, FileSetReasonEntryCount, refusal.Reason)
	assert.Empty(t, source.fetched)

	source.fetched = nil
	payload, err = ResolvePayload(record, PayloadLimits{MaxEntryBytes: entriesOf(record)[1].Size - 1}, source.fetch)
	assert.Equal(t, Payload{}, payload)
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, entriesOf(record)[1].Path, refusal.EntryPath())
	assert.Equal(t, FileSetReasonEntryBytes, refusal.Reason)
	assert.Empty(t, source.fetched, "a declared-size bound refusal fetched a payload")

	source.fetched = nil
	payload, err = ResolvePayload(
		record,
		PayloadLimits{MaxTotalBytes: entriesOf(record)[0].Size + entriesOf(record)[1].Size - 1},
		source.fetch,
	)
	assert.Equal(t, Payload{}, payload)
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, entriesOf(record)[1].Path, refusal.EntryPath())
	assert.Equal(t, FileSetReasonTotalBytes, refusal.Reason)
	assert.Empty(t, source.fetched, "a declared-size bound refusal fetched a payload")
}

func mustPayloadRawCID(t *testing.T, payload []byte) []byte {
	t.Helper()
	cid, err := RawPayloadCID(payload)
	require.NoError(t, err)
	return cid
}

func TestResolvePayloadChargesEverySegmentToTheRecordBudget(t *testing.T) {
	first, firstContents := newFileSetPayloadFixture(
		t,
		fileSetFile{path: "alpha.conf", mode: 0o600, content: []byte("synthetic alpha")},
		fileSetFile{path: "gamma.conf", mode: 0o600, content: []byte("synthetic gamma payload")},
	)
	second, secondContents := newFileSetPayloadFixture(
		t,
		fileSetFile{path: "beta.conf", mode: 0o600, content: []byte("synthetic beta payload")},
	)
	first.Segments = append(first.Segments, SnapshotSegment{
		Target: model.Target{
			ID: "other", Source: model.SourceFiles, SourceVersion: model.SourceVersion,
			Root: &model.FileRoot{Base: model.RootHome, Path: "other", Kind: model.SelectionDirectory},
		},
		Form:    SegmentFormEntries,
		Entries: second.Segments[0].Entries,
	})
	raw, err := EncodeSnapshot(first)
	require.NoError(t, err)
	record, err := DecodeSnapshot(raw)
	require.NoError(t, err)

	source := newPayloadFetchMap()
	for _, segment := range record.Segments {
		for _, entry := range segment.Entries {
			content, ok := firstContents[entry.Path]
			if !ok {
				content = secondContents[entry.Path]
			}
			source.blobs[string(entry.Blob.CID)] = bytes.Clone(content)
		}
	}

	alphaSize := uint64(len(firstContents["alpha.conf"]))
	gammaSize := uint64(len(firstContents["gamma.conf"]))
	betaSize := uint64(len(secondContents["beta.conf"]))
	payload, err := ResolvePayload(
		record, PayloadLimits{MaxTotalBytes: alphaSize + gammaSize + betaSize - 1}, source.fetch,
	)
	assert.Equal(t, Payload{}, payload)
	require.ErrorIs(t, err, ErrFileSetPayload)
	var refusal *FileSetPayloadError
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, FileSetReasonTotalBytes, refusal.Reason)
	assert.Empty(t, source.fetched, "a declared-size bound refusal fetched a payload")

	t.Run("per segment entry budget", func(t *testing.T) {
		payload, err := ResolvePayload(record, PayloadLimits{MaxEntries: 1}, source.fetch)
		assert.Equal(t, Payload{}, payload)
		require.ErrorIs(t, err, ErrFileSetPayload)
		var refusal *FileSetPayloadError
		require.ErrorAs(t, err, &refusal)
		assert.Equal(t, FileSetReasonEntryCount, refusal.Reason)
	})

	source.fetched = nil
	payload, err = ResolvePayload(
		record, PayloadLimits{MaxTotalBytes: alphaSize + gammaSize + betaSize}, source.fetch,
	)
	require.NoError(t, err)
	assert.Equal(t, PayloadFormMixed, payload.Form)
	assert.Len(t, payload.Entries, 3)
}

func TestResolvePayloadRequiresThePackedSnapshotToMatchItsSegmentTarget(t *testing.T) {
	target := model.Target{
		ID: "files", Source: model.SourceFiles, SourceVersion: model.SourceVersion,
		Root: &model.FileRoot{Base: model.RootHome, Path: "config", Kind: model.SelectionDirectory},
	}
	other := model.Target{
		ID: "files", Source: model.SourceFiles, SourceVersion: model.SourceVersion,
		Root: &model.FileRoot{Base: model.RootXDGConfig, Path: "elsewhere", Kind: model.SelectionDirectory},
	}
	for name, packedTarget := range map[string]model.Target{
		"different root": other,
	} {
		t.Run(name, func(t *testing.T) {
			packed, err := vault.Pack(model.Snapshot{
				Version: model.SnapshotVersion, Targets: []model.Target{packedTarget},
				Entries: []model.Entry{{
					TargetID: packedTarget.ID,
					File: &model.FileEntry{
						Path: "init.lua", State: model.FilePresent, Kind: model.FileRegular,
						Content: []byte("synthetic packed payload"), Mode: 0o600,
					},
				}},
			})
			require.NoError(t, err)
			record := SnapshotRecord{
				SchemaVersion: SchemaVersion, Vault: fixtureVault(), PublicationID: fixturePublicationID(),
				Segments: []SnapshotSegment{{
					Target: target, Form: SegmentFormPacked,
					Blob: BlobReference{
						CID: mustPayloadRawCID(t, packed.Payload), Size: uint64(len(packed.Payload)),
						MIMEType: SnapshotBlobMIMEType,
					},
				}},
			}
			source := newPayloadFetchMap()
			source.blobs[string(record.Segments[0].Blob.CID)] = bytes.Clone(packed.Payload)
			payload, err := ResolvePayload(record, payloadLimits(), source.fetch)
			assert.Equal(t, Payload{}, payload)
			require.ErrorIs(t, err, ErrFileSetPayload)
			var refusal *FileSetPayloadError
			require.ErrorAs(t, err, &refusal)
			assert.Equal(t, FileSetReasonMismatch, refusal.Reason)
		})
	}
}

func TestResolvePayloadRefusesAnEntryTreeThatCollidesWithADirectory(t *testing.T) {
	record := SnapshotRecord{
		SchemaVersion: SchemaVersion, Vault: fixtureVault(), PublicationID: fixturePublicationID(),
		Segments: []SnapshotSegment{{
			Target: fixtureFileSetTargets()[0], Form: SegmentFormEntries,
			Entries: []SnapshotEntry{
				fixtureEntry(t, "lua", []byte("synthetic collision"), 0o600),
				fixtureEntry(t, "lua/config", []byte("synthetic nested"), 0o600),
			},
		}},
	}
	raw, err := EncodeSnapshot(record)
	require.NoError(t, err)
	record, err = DecodeSnapshot(raw)
	require.NoError(t, err)

	source := newPayloadFetchMap()
	source.serveFileSet(record, map[string][]byte{
		"lua":        []byte("synthetic collision"),
		"lua/config": []byte("synthetic nested"),
	})
	payload, err := ResolvePayload(record, payloadLimits(), source.fetch)
	assert.Equal(t, Payload{}, payload)
	require.ErrorIs(t, err, ErrFileSetPayload)
	var refusal *FileSetPayloadError
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, FileSetReasonMismatch, refusal.Reason)
	assert.Equal(t, "lua", refusal.EntryPath())
}

func TestResolvePayloadReadsManySegmentsWithinThePerSegmentEntryBudget(t *testing.T) {
	segments := make([]SnapshotSegment, 0, 3)
	contents := make(map[string][]byte)
	for _, id := range []string{"alpha", "beta", "gamma"} {
		target := model.Target{
			ID: id, Source: model.SourceFiles, SourceVersion: model.SourceVersion,
			Root: &model.FileRoot{Base: model.RootHome, Path: id, Kind: model.SelectionDirectory},
		}
		entries := make([]SnapshotEntry, 0, 33)
		for index := range 33 {
			path := id + "-" + string(rune('a'+index)) + ".conf"
			contents[path] = []byte("synthetic repeated payload")
			entries = append(entries, fixtureEntry(t, path, contents[path], 0o600))
		}
		segments = append(segments, SnapshotSegment{
			Target: target, Form: SegmentFormEntries, Entries: entries,
		})
	}
	record := SnapshotRecord{
		SchemaVersion: SchemaVersion, Vault: fixtureVault(), PublicationID: fixturePublicationID(),
		Segments: segments,
	}
	raw, err := EncodeSnapshot(record)
	require.NoError(t, err)
	record, err = DecodeSnapshot(raw)
	require.NoError(t, err)

	source := newPayloadFetchMap()
	source.serveFileSet(record, contents)
	payload, err := ResolvePayload(record, payloadLimits(), source.fetch)
	require.NoError(t, err)
	assert.Len(t, payload.Entries, 99)
	assert.Equal(t, PayloadFormMixed, payload.Form)
}
