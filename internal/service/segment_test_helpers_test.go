package service

import (
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
)

func packedBlobFromSummaries(summaries []publicationstate.SegmentSummary) publication.BlobReference {
	for _, summary := range summaries {
		if summary.Form == publicationstate.PayloadFormPacked {
			return publication.BlobReference{
				CID: summary.BlobCID, Size: summary.BlobSize, MIMEType: publication.SnapshotBlobMIMEType,
			}
		}
	}
	return publication.BlobReference{}
}

func floorPackedBlob(floor publicationstate.Floor) publication.BlobReference {
	return packedBlobFromSummaries(floor.Segments)
}

func proposalPackedBlob(proposal MaterialPublishProposal) publication.BlobReference {
	return packedBlobFromSummaries(proposal.Proposal.CandidateSegments)
}

func proposalPackedPayload(proposal MaterialPublishProposal) []byte {
	for index, summary := range proposal.Proposal.CandidateSegments {
		if summary.Form == publicationstate.PayloadFormPacked && index < len(proposal.Candidate.Payloads) {
			return proposal.Candidate.Payloads[index]
		}
	}
	return nil
}

func floorFileSet(floor publicationstate.Floor) []publicationstate.PayloadEntryReference {
	for _, summary := range floor.Segments {
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

func recordFileSetEntries(record publication.SnapshotRecord) []publication.SnapshotEntry {
	entries, _ := record.SegmentEntries()
	return entries
}
