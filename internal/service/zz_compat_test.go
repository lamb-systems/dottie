package service

import (
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
)

func testSegmentsOf(value any) []publicationstate.SegmentSummary {
	switch typed := value.(type) {
	case publicationstate.Floor:
		return typed.Segments
	case *publicationstate.Floor:
		return typed.Segments
	case publicationstate.Attempt:
		return typed.Segments
	case *publicationstate.Attempt:
		return typed.Segments
	case publicationstate.CandidateInput:
		return nil
	case publication.SnapshotRecord:
		segments, _ := recordSummaries(typed)
		return segments
	}
	return nil
}

func recordSummaries(record publication.SnapshotRecord) ([]publicationstate.SegmentSummary, error) {
	raw, err := publication.EncodeSnapshot(record)
	if err != nil {
		return nil, err
	}
	decoded, err := publication.DecodeSnapshot(raw)
	if err != nil {
		return nil, err
	}
	return publicationstateSummaries(decoded), nil
}

func publicationstateSummaries(record publication.SnapshotRecord) []publicationstate.SegmentSummary {
	summaries := make([]publicationstate.SegmentSummary, 0, len(record.Segments))
	for _, segment := range record.Segments {
		summary := publicationstate.SegmentSummary{TargetID: segment.Target.ID}
		switch segment.Form {
		case publication.SegmentFormPacked:
			summary.Form = publicationstate.PayloadFormPacked
			testBlobCID(summary) = segment.Blob.CID
			testBlobSize(summary) = segment.Blob.Size
		case publication.SegmentFormSettings:
			summary.Form = publicationstate.PayloadFormSettings
			summary.Settings = publication.SettingsDigest(segment.Settings)
		case publication.SegmentFormEntries:
			summary.Form = publicationstate.PayloadFormFileSet
			for _, entry := range segment.Entries {
				summary.Entries = append(summary.Entries, publicationstate.PayloadEntryReference{
					Path: entry.Path, CID: entry.Blob.CID, Size: entry.Size,
				})
			}
		}
		summaries = append(summaries, summary)
	}
	return summaries
}

func proposalPackedBlob(proposal MaterialPublishProposal) publication.BlobReference {
	for index, summary := range proposal.Proposal.CandidateSegments {
		if summary.Form == publicationstate.PayloadFormPacked && index < len(proposal.Candidate.Payloads) {
			return publication.BlobReference{
				CID: testBlobCID(summary), Size: testBlobSize(summary), MIMEType: publication.SnapshotBlobMIMEType,
			}
		}
	}
	return publication.BlobReference{}
}

func testBlobCID(value any) []byte {
	for _, summary := range testSegmentsOf(value) {
		if summary.Form == publicationstate.PayloadFormPacked {
			return testBlobCID(summary)
		}
	}
	return nil
}

func testBlobSize(value any) uint64 {
	for _, summary := range testSegmentsOf(value) {
		if summary.Form == publicationstate.PayloadFormPacked {
			return testBlobSize(summary)
		}
	}
	return 0
}

func floorFileSet(value any) []publicationstate.PayloadEntryReference {
	for _, summary := range testSegmentsOf(value) {
		if summary.Form == publicationstate.PayloadFormFileSet {
			return summary.Entries
		}
	}
	return nil
}

func acceptedEntriesOf(material publicationstate.AcceptedMaterial) []publicationstate.AcceptedMaterialEntry {
	entries := make([]publicationstate.AcceptedMaterialEntry, 0)
	for _, segment := range material.Segments {
		entries = append(entries, segment.Entries...)
	}
	return entries
}
