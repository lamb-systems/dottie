package cli

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
)

func cliRecordSummaries(t *testing.T, record publication.SnapshotRecord) []publicationstate.SegmentSummary {
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

func cliRecordFileSetEntries(record publication.SnapshotRecord) []publication.SnapshotEntry {
	entries, _ := record.SegmentEntries()
	return entries
}

func cliRecordPackedBlob(record publication.SnapshotRecord) publication.BlobReference {
	return record.BlobReference()
}

func cliFloorFileSet(floor publicationstate.Floor) []publicationstate.PayloadEntryReference {
	for _, summary := range floor.Segments {
		if summary.Form == publicationstate.PayloadFormFileSet {
			return summary.Entries
		}
	}
	return nil
}

func cliFloorPackedBlob(floor publicationstate.Floor) publication.BlobReference {
	for _, summary := range floor.Segments {
		if summary.Form == publicationstate.PayloadFormPacked {
			return publication.BlobReference{
				CID: summary.BlobCID, Size: summary.BlobSize, MIMEType: publication.SnapshotBlobMIMEType,
			}
		}
	}
	return publication.BlobReference{}
}

func cliAcceptedEntries(material publicationstate.AcceptedMaterial) []publicationstate.AcceptedMaterialEntry {
	entries := make([]publicationstate.AcceptedMaterialEntry, 0)
	for _, segment := range material.Segments {
		entries = append(entries, segment.Entries...)
	}
	return entries
}

func cliAcceptedPayload(material publicationstate.AcceptedMaterial) []byte {
	for _, segment := range material.Segments {
		if segment.Summary.Form == publicationstate.PayloadFormPacked {
			return segment.Blob
		}
	}
	return nil
}

func cliAcceptedSegment(t *testing.T, targetID string) publicationstate.AcceptedMaterialSegment {
	t.Helper()
	return publicationstate.AcceptedMaterialSegment{
		Summary: publicationstate.SegmentSummary{
			TargetID: targetID, Form: publicationstate.PayloadFormFileSet,
		},
	}
}

func cliEncodedPackedSegments(t *testing.T) []byte {
	t.Helper()
	encoded, err := publicationstate.EncodeSegmentSummaries([]publicationstate.SegmentSummary{{
		TargetID: "files", Form: publicationstate.PayloadFormPacked,
		BlobCID: []byte{0x01, 0x55, 0x12}, BlobSize: 8,
	}})
	require.NoError(t, err)
	return encoded
}
