package local_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
)

func recordPackedBlob(record publication.SnapshotRecord) publication.BlobReference {
	return record.BlobReference()
}

func recordFileSetEntries(record publication.SnapshotRecord) []publication.SnapshotEntry {
	entries, _ := record.SegmentEntries()
	return entries
}

func recordSummaries(t *testing.T, record publication.SnapshotRecord) []publicationstate.SegmentSummary {
	t.Helper()
	summaries := make([]publicationstate.SegmentSummary, 0, len(record.Segments))
	for _, segment := range record.Segments {
		summary := publicationstate.SegmentSummary{TargetID: segment.Target.ID}
		switch segment.Form {
		case publication.SegmentFormPacked:
			summary.Form = publicationstate.PayloadFormPacked
			summary.BlobCID = segment.Blob.CID
			summary.BlobSize = segment.Blob.Size
		case publication.SegmentFormEntries:
			summary.Form = publicationstate.PayloadFormFileSet
			for _, entry := range segment.Entries {
				summary.Entries = append(summary.Entries, publicationstate.PayloadEntryReference{
					Path: entry.Path, CID: entry.Blob.CID, Size: entry.Size,
				})
			}
		case publication.SegmentFormSettings:
			summary.Form = publicationstate.PayloadFormSettings
			summary.Settings = publication.SettingsDigest(segment.Settings)
		}
		summaries = append(summaries, summary)
	}
	return summaries
}

func floorPackedBlob(floor publicationstate.Floor) publication.BlobReference {
	for _, summary := range floor.Segments {
		if summary.Form == publicationstate.PayloadFormPacked {
			return publication.BlobReference{
				CID: summary.BlobCID, Size: summary.BlobSize, MIMEType: publication.SnapshotBlobMIMEType,
			}
		}
	}
	return publication.BlobReference{}
}

func floorFileSet(floor publicationstate.Floor) []publicationstate.PayloadEntryReference {
	for _, summary := range floor.Segments {
		if summary.Form == publicationstate.PayloadFormFileSet {
			return summary.Entries
		}
	}
	return nil
}

func acceptedPackedPayload(material publicationstate.AcceptedMaterial) []byte {
	for _, segment := range material.Segments {
		if segment.Summary.Form == publicationstate.PayloadFormPacked {
			return segment.Blob
		}
	}
	return nil
}

func uploadPackedPayload(upload publicationstate.UploadMaterial) []byte {
	for index, summary := range upload.Segments {
		if summary.Form == publicationstate.PayloadFormPacked && index < len(upload.Payloads) {
			return upload.Payloads[index]
		}
	}
	return nil
}

func uploadPackedBlob(upload publicationstate.UploadMaterial) publication.BlobReference {
	for _, summary := range upload.Segments {
		if summary.Form == publicationstate.PayloadFormPacked {
			return publication.BlobReference{
				CID: summary.BlobCID, Size: summary.BlobSize, MIMEType: publication.SnapshotBlobMIMEType,
			}
		}
	}
	return publication.BlobReference{}
}

func resolvedRecord(
	t *testing.T,
	blobs atproto.VaultReader,
	did string,
	record publication.SnapshotRecord,
) (publication.Payload, publicationstate.MaterialInput) {
	t.Helper()
	fetch := func(blob publication.BlobReference) ([]byte, error) {
		return blobs.FetchBlob(context.Background(), did, blob.CID, int64(blob.Size))
	}
	payload, err := publication.ResolvePayload(record, publication.PayloadLimits{
		MaxEntries: publication.MaxSnapshotEntries, MaxEntryBytes: publication.MaxBlobBytes,
		MaxTotalBytes: publication.MaxBlobBytes,
	}, fetch)
	require.NoError(t, err)
	material := publicationstate.MaterialInput{Payloads: make([][]byte, len(record.Segments))}
	entryIndex := 0
	for index, segment := range record.Segments {
		switch segment.Form {
		case publication.SegmentFormPacked:
			raw, err := fetch(segment.Blob)
			require.NoError(t, err)
			material.Payloads[index] = raw
		case publication.SegmentFormEntries:
			for range segment.Entries {
				require.Less(t, entryIndex, len(payload.Entries))
				material.Entries = append(material.Entries, payload.Entries[entryIndex])
				entryIndex++
			}
		}
	}
	return payload, material
}

func localPackedCandidateInput(
	t *testing.T,
	recordRaw []byte,
	payload []byte,
) ([]publicationstate.CandidateSegment, [][]byte) {
	t.Helper()
	record, err := publication.DecodeSnapshot(recordRaw)
	require.NoError(t, err)
	require.NotEmpty(t, record.Segments)
	segment := record.Segments[0]
	require.Equal(t, publication.SegmentFormPacked, segment.Form)
	blob := segment.Blob
	return []publicationstate.CandidateSegment{{
		TargetID: segment.Target.ID, Form: publicationstate.PayloadFormPacked, Blob: &blob,
	}}, [][]byte{payload}
}
