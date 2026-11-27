package publicationstate

import (
	"bytes"

	"github.com/lamb-systems/dottie/internal/publication"
)

func attemptCandidate(f fixture, sequence uint64) CandidateInput {
	block := f.blocks[sequence]
	observation := f.observation(int(sequence + 1))
	segments, payloads := fixtureCandidateSegments(block.Raw, f.payload)
	return CandidateInput{
		SnapshotKey:    block.Key,
		SnapshotRecord: bytes.Clone(block.Raw),
		HeadRecord:     bytes.Clone(observation.Head),
		Segments:       segments,
		Payloads:       payloads,
	}
}

func fixtureCandidateSegments(recordRaw, payload []byte) ([]CandidateSegment, [][]byte) {
	record, err := publication.DecodeSnapshot(recordRaw)
	if err != nil || len(record.Segments) == 0 {
		return nil, nil
	}
	segments := make([]CandidateSegment, 0, len(record.Segments))
	payloads := make([][]byte, 0, len(record.Segments))
	for _, segment := range record.Segments {
		item := CandidateSegment{TargetID: segment.Target.ID, Form: summaryOfSegment(segment).Form}
		switch segment.Form {
		case publication.SegmentFormPacked:
			blob := segment.Blob
			item.Blob = &blob
			payloads = append(payloads, bytes.Clone(payload))
		case publication.SegmentFormEntries:
			for _, entry := range segment.Entries {
				item.Entries = append(item.Entries, PayloadEntryReference{
					Path: entry.Path, CID: bytes.Clone(entry.Blob.CID), Size: entry.Size,
				})
			}
			payloads = append(payloads, nil)
		case publication.SegmentFormSettings:
			item.SettingsDigest = summaryOfSegment(segment).Settings
			payloads = append(payloads, nil)
		default:
			return nil, nil
		}
		segments = append(segments, item)
	}
	return segments, payloads
}

func attemptView(f fixture, observation Observation, empty bool) SuppliedRepositoryView {
	scope := ViewScopeWholeRepository
	if f.binding.Backend == BackendSpaces {
		scope = ViewScopeDedicatedSpace
	}
	view := SuppliedRepositoryView{
		Origin:          f.binding,
		Scope:           scope,
		SuppliedContext: cloneContext(observation.SuppliedContext),
	}
	if !empty {
		view.Head = bytes.Clone(observation.Head)
		view.Snapshots = cloneSnapshotBlocks(observation.Snapshots)
	}
	return view
}

func attemptReview() LocalReviewContext {
	var review LocalReviewContext
	review.SelectionDigest[0] = 1
	review.ApprovalDigest[0] = 2
	review.SelectionRevision = 1
	review.ApprovalRevision = 1
	return review
}
