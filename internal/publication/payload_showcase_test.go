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

func (source *payloadFetchMap) serveShowcase(record SnapshotRecord, contents map[string][]byte) {
	for _, entry := range record.Entries {
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

type showcaseFile struct {
	path    string
	mode    uint32
	content []byte
}

func newShowcasePayloadFixture(t *testing.T, files ...showcaseFile) (SnapshotRecord, map[string][]byte) {
	t.Helper()
	sorted := slices.Clone(files)
	slices.SortFunc(sorted, func(left, right showcaseFile) int {
		return strings.Compare(left.path, right.path)
	})
	record := SnapshotRecord{SchemaVersion: SchemaVersion, Vault: fixtureVault(), PublicationID: fixturePublicationID()}
	contents := make(map[string][]byte, len(sorted))
	for _, file := range sorted {
		record.Entries = append(record.Entries, fixtureEntry(t, file.path, file.content, file.mode))
		contents[file.path] = file.content
	}
	return record, contents
}

func defaultShowcasePayloadFixture(t *testing.T) (SnapshotRecord, map[string][]byte) {
	t.Helper()
	return newShowcasePayloadFixture(
		t,
		showcaseFile{path: "init.lua", mode: 0o600, content: []byte("showcase init")},
		showcaseFile{path: "lua/config/options.lua", mode: 0o644, content: []byte("showcase options")},
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
	record.Blob = BlobReference{
		CID: mustPayloadRawCID(t, packed.Payload), Size: uint64(len(packed.Payload)),
		MIMEType: SnapshotBlobMIMEType,
	}
	source := newPayloadFetchMap()
	source.blobs[string(record.Blob.CID)] = bytes.Clone(packed.Payload)

	payload, err := ResolvePayload(record, payloadLimits(), source.fetch)
	require.NoError(t, err)
	assert.Equal(t, PayloadFormPacked, payload.Form)
	assert.Equal(t, snapshot, payload.Snapshot)
	assert.Empty(t, payload.Entries)
	require.Len(t, source.fetched, 1)
	assert.Equal(t, record.Blob, source.fetched[0].reference)

	resolved, err := payload.PackedSnapshot()
	require.NoError(t, err)
	assert.Equal(t, snapshot, resolved)
}

func TestResolvePayloadReadsShowcaseEntriesWithPathsModesAndSizes(t *testing.T) {
	record, contents := defaultShowcasePayloadFixture(t)
	source := newPayloadFetchMap()
	source.serveShowcase(record, contents)

	payload, err := ResolvePayload(record, payloadLimits(), source.fetch)
	require.NoError(t, err)
	assert.Equal(t, PayloadFormShowcase, payload.Form)
	assert.Equal(t, model.Snapshot{}, payload.Snapshot)
	require.Len(t, payload.Entries, len(record.Entries))
	for index, entry := range record.Entries {
		assert.Equal(t, entry.Path, payload.Entries[index].Path)
		assert.Equal(t, entry.Mode, payload.Entries[index].Mode)
		assert.Equal(t, entry.Size, payload.Entries[index].Size)
		assert.Equal(t, contents[entry.Path], payload.Entries[index].Content)
		assert.Equal(t, entry.Blob, source.fetched[index].reference)
	}

	snapshot, err := payload.PackedSnapshot()
	assert.Equal(t, model.Snapshot{}, snapshot)
	require.ErrorIs(t, err, ErrShowcasePayload)
}

func TestResolvePayloadRefusesAMissingShowcaseEntryNamingThePath(t *testing.T) {
	record, contents := defaultShowcasePayloadFixture(t)
	missing := record.Entries[1]
	source := newPayloadFetchMap()
	source.blobs[string(record.Entries[0].Blob.CID)] = contents[record.Entries[0].Path]
	source.fails[string(missing.Blob.CID)] = errPayloadFetchMissing

	payload, err := ResolvePayload(record, payloadLimits(), source.fetch)
	assert.Equal(t, Payload{}, payload)
	require.ErrorIs(t, err, ErrShowcasePayload)
	require.ErrorIs(t, err, errPayloadFetchMissing)
	var refusal *ShowcasePayloadError
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, missing.Path, refusal.EntryPath())
	assert.Equal(t, ShowcaseReasonUnavailable, refusal.Reason)
	assert.Contains(t, err.Error(), missing.Path)
	require.Len(t, source.fetched, 2)
}

func TestResolvePayloadRefusesAShowcaseEntrySizeMismatchNamingTheEntry(t *testing.T) {
	record, contents := defaultShowcasePayloadFixture(t)
	mismatched := record.Entries[1]
	short := bytes.Clone(contents[mismatched.Path])
	short = short[:len(short)-1]
	source := newPayloadFetchMap()
	source.blobs[string(record.Entries[0].Blob.CID)] = contents[record.Entries[0].Path]
	source.blobs[string(mismatched.Blob.CID)] = short

	payload, err := ResolvePayload(record, payloadLimits(), source.fetch)
	assert.Equal(t, Payload{}, payload)
	require.ErrorIs(t, err, ErrShowcasePayload)
	require.ErrorIs(t, err, ErrPayload)
	var refusal *ShowcasePayloadError
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, mismatched.Path, refusal.EntryPath())
	assert.Equal(t, ShowcaseReasonMismatch, refusal.Reason)
	var violationErr *ViolationError
	require.ErrorAs(t, err, &violationErr)
	assert.Equal(t, "blob.size", violationErr.Field())
	assert.Equal(t, "mismatch", violationErr.Reason())
}

func TestResolvePayloadRefusesAShowcaseEntryCIDMismatchNamingTheEntry(t *testing.T) {
	record, contents := defaultShowcasePayloadFixture(t)
	mismatched := record.Entries[1]
	substitute := bytes.Clone(contents[mismatched.Path])
	substitute[0] ^= 0xff
	source := newPayloadFetchMap()
	source.blobs[string(record.Entries[0].Blob.CID)] = contents[record.Entries[0].Path]
	source.blobs[string(mismatched.Blob.CID)] = substitute

	payload, err := ResolvePayload(record, payloadLimits(), source.fetch)
	assert.Equal(t, Payload{}, payload)
	require.ErrorIs(t, err, ErrShowcasePayload)
	var refusal *ShowcasePayloadError
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, mismatched.Path, refusal.EntryPath())
	assert.Equal(t, ShowcaseReasonMismatch, refusal.Reason)
	var violationErr *ViolationError
	require.ErrorAs(t, err, &violationErr)
	assert.Equal(t, "blob.ref", violationErr.Field())
}

func TestResolvePayloadRefusesShowcasePayloadsBeyondItsBounds(t *testing.T) {
	record, contents := defaultShowcasePayloadFixture(t)
	source := newPayloadFetchMap()
	source.serveShowcase(record, contents)
	var refusal *ShowcasePayloadError

	payload, err := ResolvePayload(record, PayloadLimits{MaxEntries: 1}, source.fetch)
	assert.Equal(t, Payload{}, payload)
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, ShowcaseReasonEntryCount, refusal.Reason)
	assert.Empty(t, source.fetched)

	source.fetched = nil
	payload, err = ResolvePayload(record, PayloadLimits{MaxEntryBytes: record.Entries[1].Size - 1}, source.fetch)
	assert.Equal(t, Payload{}, payload)
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, record.Entries[1].Path, refusal.EntryPath())
	assert.Equal(t, ShowcaseReasonEntryBytes, refusal.Reason)
	require.Len(t, source.fetched, 1)
	assert.Equal(t, record.Entries[0].Blob, source.fetched[0].reference)

	source.fetched = nil
	payload, err = ResolvePayload(
		record,
		PayloadLimits{MaxTotalBytes: record.Entries[0].Size + record.Entries[1].Size - 1},
		source.fetch,
	)
	assert.Equal(t, Payload{}, payload)
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, record.Entries[1].Path, refusal.EntryPath())
	assert.Equal(t, ShowcaseReasonTotalBytes, refusal.Reason)
	require.Len(t, source.fetched, 1)
	assert.Equal(t, record.Entries[0].Blob, source.fetched[0].reference)
}

func mustPayloadRawCID(t *testing.T, payload []byte) []byte {
	t.Helper()
	cid, err := RawPayloadCID(payload)
	require.NoError(t, err)
	return cid
}
