package publicationstate

import "bytes"

func attemptCandidate(f fixture, sequence uint64) CandidateInput {
	block := f.blocks[sequence]
	observation := f.observation(int(sequence + 1))
	return CandidateInput{SnapshotKey: block.Key, SnapshotRecord: bytes.Clone(block.Raw), HeadRecord: bytes.Clone(observation.Head), Payload: bytes.Clone(f.payload)}
}

func attemptView(f fixture, observation Observation, empty bool) SuppliedRepositoryView {
	scope := ViewScopeWholeRepository
	if f.binding.Backend == BackendSpaces {
		scope = ViewScopeDedicatedSpace
	}
	view := SuppliedRepositoryView{Origin: f.binding, Scope: scope, SuppliedContext: cloneContext(observation.SuppliedContext)}
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
