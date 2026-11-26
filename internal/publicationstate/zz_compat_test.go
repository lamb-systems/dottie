package publicationstate

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/publication"
)

func testSegmentsOf(value any) []SegmentSummary {
	switch typed := value.(type) {
	case Floor:
		return typed.Segments
	case *Floor:
		return typed.Segments
	case Attempt:
		return typed.Segments
	case *Attempt:
		return typed.Segments
	case attemptCoreWire:
		segments, _ := segmentSummariesFromWire(typed.Segments)
		return segments
	case *attemptCoreWire:
		segments, _ := segmentSummariesFromWire(typed.Segments)
		return segments
	case AcceptedMaterial:
		summaries := make([]SegmentSummary, 0, len(typed.Segments))
		for _, segment := range typed.Segments {
			summaries = append(summaries, segment.Summary)
		}
		return summaries
	case *AcceptedMaterial:
		return testSegmentsOf(*typed)
	case []SegmentSummary:
		return typed
	case SegmentSummary:
		return []SegmentSummary{typed}
	case *SegmentSummary:
		return []SegmentSummary{*typed}
	}
	return nil
}

func testBlobCID(value any) []byte {
	for _, summary := range testSegmentsOf(value) {
		if summary.Form == PayloadFormPacked {
			return summary.BlobCID
		}
	}
	return nil
}

func testBlobSize(value any) uint64 {
	for _, summary := range testSegmentsOf(value) {
		if summary.Form == PayloadFormPacked {
			return summary.BlobSize
		}
	}
	return 0
}

func testFileSet(value any) *FileSetPayload {
	for _, summary := range testSegmentsOf(value) {
		if summary.Form == PayloadFormFileSet {
			return &FileSetPayload{Entries: summary.Entries}
		}
	}
	return nil
}

func fileSetEntries(value any) []PayloadEntryReference {
	fileSet := testFileSet(value)
	if fileSet == nil {
		return nil
	}
	return fileSet.Entries
}

func acceptedPayload(value any) []byte {
	switch material := value.(type) {
	case AcceptedMaterial:
		for _, segment := range material.Segments {
			if segment.Summary.Form == PayloadFormPacked {
				return segment.Blob
			}
		}
	case *AcceptedMaterial:
		return acceptedPayload(*material)
	case CandidateInput:
		return material.Payload
	case *CandidateInput:
		return material.Payload
	case UploadMaterial:
		for index, summary := range material.Segments {
			if summary.Form == PayloadFormPacked && index < len(material.Payloads) {
				return material.Payloads[index]
			}
		}
	case CandidateMaterial:
		for index, summary := range material.Segments {
			if summary.Form == PayloadFormPacked && index < len(material.Payloads) {
				return material.Payloads[index]
			}
		}
	}
	return nil
}

func acceptedEntries(value any) []AcceptedMaterialEntry {
	entries := make([]AcceptedMaterialEntry, 0)
	material, ok := value.(AcceptedMaterial)
	if !ok {
		if pointer, pointerOK := value.(*AcceptedMaterial); pointerOK {
			material, ok = *pointer, true
		}
	}
	if !ok {
		return entries
	}
	for _, segment := range material.Segments {
		entries = append(entries, segment.Entries...)
	}
	return entries
}

func testBlob(value any) publication.BlobReference {
	switch typed := value.(type) {
	case publication.SnapshotRecord:
		blob, _ := typed.SegmentBlob()
		return blob
	case *publication.SnapshotRecord:
		return testBlob(*typed)
	case CandidateInput:
		for _, segment := range typed.Segments {
			if segment.Form == PayloadFormPacked && segment.Blob != nil {
				return *segment.Blob
			}
		}
	case *CandidateInput:
		return testBlob(*typed)
	}
	return publication.BlobReference{}
}

func materialBlob(value CandidateMaterial) publication.BlobReference {
	for index, summary := range value.Segments {
		if summary.Form == PayloadFormPacked && index < len(value.Payloads) {
			return publication.BlobReference{
				CID: summary.BlobCID, Size: summary.BlobSize, MIMEType: publication.SnapshotBlobMIMEType,
			}
		}
	}
	return publication.BlobReference{}
}

func testUploadBlob(value UploadMaterial) publication.BlobReference {
	for index, summary := range value.Segments {
		if summary.Form == PayloadFormPacked && index < len(value.Payloads) {
			return publication.BlobReference{
				CID: summary.BlobCID, Size: summary.BlobSize, MIMEType: publication.SnapshotBlobMIMEType,
			}
		}
	}
	return publication.BlobReference{}
}

func uploadPayload(value UploadMaterial) []byte {
	for index, summary := range value.Segments {
		if summary.Form == PayloadFormPacked && index < len(value.Payloads) {
			return value.Payloads[index]
		}
	}
	return nil
}

func recordEntriesOf(record publication.SnapshotRecord) []publication.SnapshotEntry {
	entries, _ := record.SegmentEntries()
	return entries
}

func ownerName(owner materialOwnership) string {
	for _, summary := range owner.segments {
		if summary.Form == PayloadFormPacked {
			name, err := payloadBasenameFromCID(summary.BlobCID)
			if err == nil {
				return name
			}
		}
	}
	return ""
}

func ownerBlob(owner materialOwnership) publication.BlobReference {
	for _, summary := range owner.segments {
		if summary.Form == PayloadFormPacked {
			return publication.BlobReference{
				CID: summary.BlobCID, Size: summary.BlobSize, MIMEType: publication.SnapshotBlobMIMEType,
			}
		}
	}
	return publication.BlobReference{}
}

func incomingMaterialUpgradeStoredMetadata(t *testing.T, ctx context.Context, q queryer) map[string][]byte {
	t.Helper()
	rows, err := q.QueryContext(ctx, "SELECT key,value FROM store_meta ORDER BY key")
	require.NoError(t, err)
	defer func() { assert.NoError(t, rows.Close()) }()
	metadata := make(map[string][]byte)
	for rows.Next() {
		var key string
		var value []byte
		require.NoError(t, rows.Scan(&key, &value))
		metadata[key] = bytes.Clone(value)
	}
	require.NoError(t, rows.Err())
	return metadata
}

func b8TestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func b8Count(t *testing.T, ctx context.Context, q queryer, query string, args ...any) int64 {
	t.Helper()
	var count int64
	require.NoError(t, q.QueryRowContext(ctx, query, args...).Scan(&count))
	return count
}

func b8IncomingRows(t *testing.T, ctx context.Context, q queryer) [][]any {
	t.Helper()
	rows, err := q.QueryContext(
		ctx,
		"SELECT accepted_revision,record_cid,segments FROM accepted_material_refs ORDER BY accepted_revision",
	)
	require.NoError(t, err)
	defer func() { assert.NoError(t, rows.Close()) }()
	var result [][]any
	for rows.Next() {
		var revision int64
		var recordCID, encoded []byte
		require.NoError(t, rows.Scan(&revision, &recordCID, &encoded))
		summaries, err := decodeSegmentSummaries(encoded)
		require.NoError(t, err)
		var blobCID []byte
		for _, summary := range summaries {
			if summary.Form == PayloadFormPacked {
				blobCID = summary.BlobCID
			}
		}
		result = append(result, []any{revision, bytes.Clone(recordCID), bytes.Clone(blobCID)})
	}
	require.NoError(t, rows.Err())
	return result
}

func requireIncomingMaterialRowsAbsent(t *testing.T, ctx context.Context, store *Store) {
	t.Helper()
	require.Zero(t, b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_material_refs"))
}

func requireIncomingMaterialLoadAbsent(t *testing.T, ctx context.Context, store *Store) {
	t.Helper()
	floor, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.False(t, present)
	require.Equal(t, Floor{}, floor)
}

func requireIncomingMaterialPublication(t *testing.T, ctx context.Context, store *Store, f fixture, floor Floor) {
	t.Helper()
	loaded, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	require.Equal(t, floor.RecordCID, loaded.RecordCID)
}

func incomingMaterialFirstUse(t *testing.T, store *Store, f fixture) Floor {
	t.Helper()
	ctx := context.Background()
	observation := f.observation(1)
	proposal := prepareFirstUse(t, store, observation, f.payload)
	floor, err := store.Accept(ctx, ModeFirstUse, proposal.StateToken, observation, f.payload, proposal.Confirmation)
	require.NoError(t, err)
	return floor
}

func incomingCustodyPlaceOrphan(t *testing.T, directory string, payload []byte) string {
	t.Helper()
	name := payloadBasename(payload)
	payloadDirectory := filepath.Join(directory, payloadDirectoryName)
	require.NoError(t, os.MkdirAll(payloadDirectory, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(payloadDirectory, name), payload, 0o600))
	return name
}

func mustPayloadRawCID(t *testing.T, payload []byte) []byte {
	t.Helper()
	cidValue, err := publication.RawPayloadCID(payload)
	require.NoError(t, err)
	return cidValue
}

func (f fileSetAttemptFixture) recordSegments() []publication.SnapshotSegment {
	record, err := publication.DecodeSnapshot(f.raw)
	if err != nil {
		return nil
	}
	return record.Segments
}

func retainedReferencesCID(t *testing.T, store *Store, cidValue []byte) int64 {
	t.Helper()
	rows, err := store.conn.QueryContext(context.Background(), "SELECT segments FROM retained_publications")
	require.NoError(t, err)
	defer func() { assert.NoError(t, rows.Close()) }()
	var matches int64
	for rows.Next() {
		var encoded []byte
		require.NoError(t, rows.Scan(&encoded))
		summaries, err := decodeSegmentSummaries(encoded)
		require.NoError(t, err)
		for _, summary := range summaries {
			if bytes.Equal(summary.BlobCID, cidValue) {
				matches++
			}
			for _, entry := range summary.Entries {
				if bytes.Equal(entry.CID, cidValue) {
					matches++
				}
			}
		}
	}
	require.NoError(t, rows.Err())
	return matches
}
