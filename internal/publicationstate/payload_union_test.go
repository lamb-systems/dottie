package publicationstate

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/publication"
)

func fixturePackedSummary() SegmentSummary {
	return SegmentSummary{TargetID: "files", Form: PayloadFormPacked, BlobCID: []byte{0x55, 0x12}, BlobSize: 4096}
}

func fixtureEntriesSummary() SegmentSummary {
	cidValue, _ := publication.RawPayloadCID([]byte("entry"))
	return SegmentSummary{
		TargetID: "desktop", Form: PayloadFormFileSet,
		Entries: []PayloadEntryReference{{Path: "init.lua", CID: cidValue, Size: 5}},
	}
}

func fixtureSettingsSummary() SegmentSummary {
	return SegmentSummary{TargetID: "shell", Form: PayloadFormSettings, Settings: [32]byte{0x01}}
}

func TestStoredAttemptWireCarriesEverySegmentForm(t *testing.T) {
	summaries := []SegmentSummary{fixtureEntriesSummary(), fixturePackedSummary(), fixtureSettingsSummary()}
	encoded, err := encodeSegmentSummaries(summaries)
	require.NoError(t, err)

	wire := attemptCoreWire{
		Version:               3,
		AttemptID:             bytes.Repeat([]byte{1}, 16),
		DatabaseID:            bytes.Repeat([]byte{2}, 32),
		SnapshotCID:           []byte{3},
		HeadCID:               []byte{4},
		Segments:              segmentSummariesToWire(summaries),
		CandidateConfirmation: bytes.Repeat([]byte{6}, 32),
		InitialViewDigest:     bytes.Repeat([]byte{7}, 32),
	}
	coreBytes, err := encodeAttemptCore(wire)
	require.NoError(t, err)
	decoded, err := decodeAttemptCore(coreBytes)
	require.NoError(t, err)
	assert.Equal(t, wire, decoded)

	roundTrip, err := decodeSegmentSummaries(encoded)
	require.NoError(t, err)
	assert.Equal(t, summaries, roundTrip)
}

func TestStoredFloorWireCarriesEverySegmentForm(t *testing.T) {
	summaries := []SegmentSummary{fixtureEntriesSummary(), fixturePackedSummary(), fixtureSettingsSummary()}
	encoded, err := encodeSegmentSummaries(summaries)
	require.NoError(t, err)
	decoded, err := decodeSegmentSummaries(encoded)
	require.NoError(t, err)
	assert.Equal(t, summaries, decoded)

	floor := Floor{
		DatabaseID: [32]byte{1}, Revision: 1, Generation: 1, Provenance: ProvenanceFirst,
		AnchorCID: []byte{2}, Binding: Binding{AccountDID: testDID, Repository: "at://" + testDID},
		Head: []byte{3}, SnapshotKey: "0000000000000000", RecordCID: []byte{4},
		Segments: summaries,
	}
	floorBytes, err := encodeFloor(floor)
	require.NoError(t, err)
	roundTrip, err := decodeFloor(floorBytes)
	require.NoError(t, err)
	assert.Equal(t, summaries, roundTrip.Segments)
}

func TestSegmentSummariesRefuseAtTheDocumentedBounds(t *testing.T) {
	require.Error(t, validateSegmentSummaries(nil))
	require.Error(t, validateSegmentSummaries([]SegmentSummary{{TargetID: "files", Form: PayloadFormPacked}}))
	require.Error(t, validateSegmentSummaries([]SegmentSummary{{TargetID: "files", Form: PayloadFormFileSet}}))
	require.Error(t, validateSegmentSummaries([]SegmentSummary{{TargetID: "files", Form: PayloadFormSettings}}))
	require.Error(t, validateSegmentSummaries([]SegmentSummary{
		{TargetID: "b", Form: PayloadFormPacked, BlobCID: []byte{1}, BlobSize: 1},
		{TargetID: "a", Form: PayloadFormPacked, BlobCID: []byte{1}, BlobSize: 1},
	}))
	require.NoError(t, validateSegmentSummaries([]SegmentSummary{fixturePackedSummary()}))
}

func TestAttemptSegmentsMustMatchTheirSnapshotRecord(t *testing.T) {
	record := publication.SnapshotRecord{
		SchemaVersion: publication.SchemaVersion,
		Vault:         [32]byte{1},
		Segments: []publication.SnapshotSegment{{
			Target: fixturePackedTarget(), Form: publication.SegmentFormPacked,
			Blob: publication.BlobReference{CID: []byte{0x55, 0x12}, Size: 4096, MIMEType: publication.SnapshotBlobMIMEType},
		}},
	}
	segments := summariesOfRecord(record.Segments)
	encoded, err := encodeSegmentSummaries(segments)
	require.NoError(t, err)
	wire := attemptCoreWire{Version: 3}
	require.NoError(t, checkAttemptCorePayload(wire))
	wire.Segments = segmentSummariesToWire(segments)
	assert.Equal(t, segments, func() []SegmentSummary {
		decoded, err := segmentSummariesFromWire(wire.Segments)
		require.NoError(t, err)
		return decoded
	}())
	assert.NotEmpty(t, encoded)
}

func TestSegmentConsumersRefuseTheWrongForm(t *testing.T) {
	packed := fixturePackedSummary()
	entries := fixtureEntriesSummary()
	settings := fixtureSettingsSummary()

	assert.Nil(t, testFileSet(packed))
	assert.NotNil(t, testFileSet(entries))
	assert.Equal(t, entries.Entries, fileSetEntries(entries))
	assert.Nil(t, fileSetEntries(packed))
	assert.Empty(t, testBlobCID(entries))
	assert.Empty(t, testBlobSize(settings))

	require.NoError(t, validateSegmentMaterialLimits(entries, DefaultAttemptLimits()))
}

func TestSegmentEvidenceHeadBindingCarriesNoPayloadCID(t *testing.T) {
	record := publication.SnapshotRecord{
		SchemaVersion: publication.SchemaVersion,
		Vault:         [32]byte{1},
		Segments: []publication.SnapshotSegment{{
			Target: fixturePackedTarget(), Form: publication.SegmentFormPacked,
			Blob: publication.BlobReference{CID: []byte{0x55, 0x12}, Size: 4096, MIMEType: publication.SnapshotBlobMIMEType},
		}},
	}
	raw, err := publication.EncodeSnapshot(record)
	require.NoError(t, err)
	recordCID, err := publication.RecordCID(raw)
	require.NoError(t, err)
	head, err := publication.EncodeHead(publication.HeadRecord{
		SchemaVersion: publication.SchemaVersion, Vault: record.Vault, SnapshotCID: recordCID,
	})
	require.NoError(t, err)
	key, err := publication.SequenceKey(0)
	require.NoError(t, err)
	assert.NoError(t, publication.VerifyHeadBinding(head, raw, key))
	assert.NotContains(t, string(head), "blobCid")
}
