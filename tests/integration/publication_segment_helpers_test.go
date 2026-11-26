package integration

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
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

func candidatePackedPayload(material publicationstate.CandidateMaterial) []byte {
	for index, summary := range material.Segments {
		if summary.Form == publicationstate.PayloadFormPacked && index < len(material.Payloads) {
			return material.Payloads[index]
		}
	}
	return nil
}

func candidatePackedBlob(material publicationstate.CandidateMaterial) publication.BlobReference {
	for _, summary := range material.Segments {
		if summary.Form == publicationstate.PayloadFormPacked {
			return publication.BlobReference{
				CID: summary.BlobCID, Size: summary.BlobSize, MIMEType: publication.SnapshotBlobMIMEType,
			}
		}
	}
	return publication.BlobReference{}
}

func uploadPackedPayload(upload publicationstate.UploadMaterial) []byte {
	for index, summary := range upload.Segments {
		if summary.Form == publicationstate.PayloadFormPacked && index < len(upload.Payloads) {
			return upload.Payloads[index]
		}
	}
	return nil
}

func packedSnapshotTarget() model.Target {
	return model.Target{
		ID: "files", Source: model.SourceFiles, SourceVersion: model.SourceVersion,
		Root: &model.FileRoot{Base: model.RootHome, Path: "config", Kind: model.SelectionDirectory},
	}
}

func recordBlobs(t *testing.T, record publication.SnapshotRecord) []publication.BlobReference {
	t.Helper()
	blobs := make([]publication.BlobReference, 0)
	for _, segment := range record.Segments {
		switch segment.Form {
		case publication.SegmentFormPacked:
			blobs = append(blobs, segment.Blob)
		case publication.SegmentFormEntries:
			for _, entry := range segment.Entries {
				blobs = append(blobs, entry.Blob)
			}
		}
	}
	return blobs
}

func candidateBlobs(t *testing.T, candidate publicationstate.CandidateInput) []publication.BlobReference {
	t.Helper()
	blobs := make([]publication.BlobReference, 0)
	entryIndex := 0
	for index, segment := range candidate.Segments {
		switch segment.Form {
		case publicationstate.PayloadFormPacked:
			payload := candidate.Payloads[index]
			cid, err := publication.RawPayloadCID(payload)
			require.NoError(t, err)
			blobs = append(blobs, publication.BlobReference{
				CID: cid, Size: uint64(len(payload)), MIMEType: publication.SnapshotBlobMIMEType,
			})
		case publicationstate.PayloadFormFileSet:
			for range segment.Entries {
				require.Less(t, entryIndex, len(candidate.Entries))
				content := candidate.Entries[entryIndex].Content
				entryIndex++
				cid, err := publication.RawPayloadCID(content)
				require.NoError(t, err)
				blobs = append(blobs, publication.BlobReference{
					CID: cid, Size: uint64(len(content)), MIMEType: publication.BlobMIMEType,
				})
			}
		}
	}
	return blobs
}
