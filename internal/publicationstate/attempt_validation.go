package publicationstate

import (
	"bytes"
	"context"
	"errors"

	"github.com/lamb-systems/dottie/internal/publication"
)

const ordinaryPublicationLimit = 4079

type validatedRepositoryView struct {
	input  SuppliedRepositoryView
	blocks []validatedRecord
	byKey  map[string]validatedRecord
	byCID  map[string]validatedRecord
	head   publication.HeadRecord
	digest [32]byte
	empty  bool
}

type validatedCandidate struct {
	kind        AttemptKind
	id          [16]byte
	sequence    uint64
	key         string
	snapshot    publication.SnapshotRecord
	head        publication.HeadRecord
	snapshotCID []byte
	headCID     []byte
	blobCID     []byte
	payload     []byte
	snapshotRaw []byte
	headRaw     []byte
	view        validatedRepositoryView
	predecessor *validatedRecord
}

func validateSuppliedRepositoryView(input SuppliedRepositoryView, binding Binding, limits Limits, allowOtherVault bool) (validatedRepositoryView, error) {
	if err := validateBinding(input.Origin); err != nil || !sameBinding(input.Origin, binding) {
		return validatedRepositoryView{}, classified(ErrInvalid, StageInput, ReasonBinding)
	}
	if err := validateContext(input.SuppliedContext, binding, limits); err != nil {
		if errors.Is(err, errContextLimit) {
			return validatedRepositoryView{}, classified(ErrLimit, StageInput, ReasonContext)
		}
		return validatedRepositoryView{}, classified(ErrInvalid, StageInput, ReasonContext)
	}
	switch binding.Backend {
	case BackendPublicRepo:
		if input.Scope != ViewScopeWholeRepository {
			return validatedRepositoryView{}, classified(ErrInvalid, StageInput, ReasonRecordSet)
		}
	case BackendSpaces:
		if input.Scope != ViewScopeDedicatedSpace {
			return validatedRepositoryView{}, classified(ErrInvalid, StageInput, ReasonRecordSet)
		}
	default:
		return validatedRepositoryView{}, classified(ErrInvalid, StageInput, ReasonBinding)
	}
	if len(input.Snapshots) == 0 {
		if len(input.Head) != 0 {
			return validatedRepositoryView{}, classified(ErrInvalid, StageInput, ReasonRecordSet)
		}
		digest, err := makeViewDigest(input, nil)
		if err != nil {
			return validatedRepositoryView{}, classified(ErrInvalid, StageInput, ReasonRecordSet)
		}
		return validatedRepositoryView{input: cloneSuppliedView(input), byKey: map[string]validatedRecord{}, byCID: map[string]validatedRecord{}, digest: digest, empty: true}, nil
	}
	if len(input.Head) == 0 || len(input.Snapshots) > int(limits.SuppliedSnapshotCount) || len(input.Head) > publication.MaxRecordBytes {
		return validatedRepositoryView{}, classified(ErrLimit, StageInput, ReasonRecordSet)
	}
	if uint64(len(input.Snapshots)-1) > uint64(limits.MaxLineageLinks) {
		return validatedRepositoryView{}, classified(ErrLimit, StageInput, ReasonRecordSet)
	}
	maxCount := uint32(4095)
	if limits.SuppliedSnapshotCount < maxCount {
		maxCount = limits.SuppliedSnapshotCount
	}
	if uint32(len(input.Snapshots)) > maxCount {
		return validatedRepositoryView{}, classified(ErrLimit, StageInput, ReasonRecordSet)
	}
	total := uint64(len(input.Head))
	if total > limits.SuppliedTotalBytes || total > 8<<20 {
		return validatedRepositoryView{}, classified(ErrLimit, StageInput, ReasonRecordSet)
	}
	blocks := make([]validatedRecord, 0, len(input.Snapshots))
	byKey := make(map[string]validatedRecord, len(input.Snapshots))
	byCID := make(map[string]validatedRecord, len(input.Snapshots))
	publicBlocks := make([]SnapshotBlock, 0, len(input.Snapshots))
	var vault [32]byte
	for index, block := range input.Snapshots {
		if len(block.Raw) == 0 || len(block.Raw) > publication.MaxRecordBytes {
			return validatedRepositoryView{}, classified(ErrLimit, StageInput, ReasonRecordSet)
		}
		total += uint64(len(block.Raw))
		if total > limits.SuppliedTotalBytes || total > 8<<20 {
			return validatedRepositoryView{}, classified(ErrLimit, StageInput, ReasonRecordSet)
		}
		sequence, err := publication.ParseSequenceKey(block.Key)
		if err != nil || sequence != uint64(index) {
			return validatedRepositoryView{}, classified(ErrInvalid, StageInput, ReasonRecordSet)
		}
		record, err := publication.DecodeSnapshot(block.Raw)
		if err != nil {
			return validatedRepositoryView{}, classified(ErrInvalid, StageInput, ReasonRecordSet)
		}
		if index == 0 {
			vault = record.Vault
			if sequence != 0 || len(record.Parent) != 0 {
				return validatedRepositoryView{}, classified(ErrInvalid, StageInput, ReasonRecordSet)
			}
		} else {
			if record.Vault != vault {
				return validatedRepositoryView{}, classified(ErrInvalid, StageInput, ReasonRecordSet)
			}
			if err := publication.VerifySuccessor(blocks[index-1].raw, block.Raw, block.Key); err != nil {
				return validatedRepositoryView{}, classified(ErrInvalid, StageInput, ReasonRecordSet)
			}
		}
		if !allowOtherVault && record.Vault != binding.Vault {
			return validatedRepositoryView{}, classified(ErrInvalid, StageInput, ReasonBinding)
		}
		cid, err := publication.RecordCID(block.Raw)
		if err != nil {
			return validatedRepositoryView{}, classified(ErrInvalid, StageInput, ReasonRecordSet)
		}
		if _, ok := byKey[block.Key]; ok {
			return validatedRepositoryView{}, classified(ErrInvalid, StageInput, ReasonRecordSet)
		}
		if _, ok := byCID[string(cid)]; ok {
			return validatedRepositoryView{}, classified(ErrInvalid, StageInput, ReasonRecordSet)
		}
		ref := RecordReference{Key: block.Key, CID: bytes.Clone(cid), Sequence: sequence}
		validated := validatedRecord{ref: ref, raw: bytes.Clone(block.Raw)}
		blocks = append(blocks, validated)
		byKey[block.Key] = validated
		byCID[string(cid)] = validated
		publicBlocks = append(publicBlocks, SnapshotBlock{Key: block.Key, Raw: bytes.Clone(block.Raw)})
	}
	head, err := publication.DecodeHead(input.Head)
	if err != nil || head.Vault != vault {
		return validatedRepositoryView{}, classified(ErrInvalid, StageInput, ReasonRecordSet)
	}
	last := blocks[len(blocks)-1]
	if head.PublicationSeq != last.ref.Sequence || !bytes.Equal(head.SnapshotCID, last.ref.CID) || publication.VerifyHeadBinding(input.Head, last.raw, last.ref.Key) != nil {
		return validatedRepositoryView{}, classified(ErrInvalid, StageInput, ReasonRecordSet)
	}
	digest, err := makeViewDigest(input, publicBlocks)
	if err != nil {
		return validatedRepositoryView{}, classified(ErrInvalid, StageInput, ReasonRecordSet)
	}
	return validatedRepositoryView{input: cloneSuppliedView(input), blocks: blocks, byKey: byKey, byCID: byCID, head: head, digest: digest}, nil
}

func validateCandidateInput(input CandidateInput, binding Binding) (validatedCandidate, error) {
	if len(input.SnapshotRecord) == 0 || len(input.SnapshotRecord) > publication.MaxRecordBytes || len(input.HeadRecord) == 0 || len(input.HeadRecord) > publication.MaxRecordBytes || len(input.Payload) == 0 || uint64(len(input.Payload)) > publication.MaxBlobBytes {
		return validatedCandidate{}, classified(ErrLimit, StageInput, ReasonRecordSet)
	}
	snapshot, err := publication.DecodeSnapshot(input.SnapshotRecord)
	if err != nil || snapshot.Vault != binding.Vault || allZero(snapshot.PublicationID[:]) {
		return validatedCandidate{}, classified(ErrInvalid, StageInput, ReasonRecordSet)
	}
	key, err := publication.SequenceKey(snapshot.PublicationSeq)
	if err != nil || input.SnapshotKey != key {
		return validatedCandidate{}, classified(ErrInvalid, StageInput, ReasonRecordSet)
	}
	snapshotCID, err := publication.RecordCID(input.SnapshotRecord)
	if err != nil {
		return validatedCandidate{}, classified(ErrInvalid, StageInput, ReasonRecordSet)
	}
	head, err := publication.DecodeHead(input.HeadRecord)
	if err != nil || head.Vault != binding.Vault || head.PublicationSeq != snapshot.PublicationSeq || !bytes.Equal(head.SnapshotCID, snapshotCID) || !bytes.Equal(head.BlobCID, snapshot.Blob.CID) || publication.VerifyHeadBinding(input.HeadRecord, input.SnapshotRecord, input.SnapshotKey) != nil {
		return validatedCandidate{}, classified(ErrInvalid, StageInput, ReasonRecordSet)
	}
	headCID, err := publication.RecordCID(input.HeadRecord)
	if err != nil {
		return validatedCandidate{}, classified(ErrInvalid, StageInput, ReasonRecordSet)
	}
	if err := publication.VerifyPayload(input.Payload, snapshot.Blob); err != nil {
		return validatedCandidate{}, classified(ErrInvalid, StageInput, ReasonRecordSet)
	}
	if _, err := publication.DecodePayload(input.Payload, snapshot.Blob); err != nil {
		return validatedCandidate{}, classified(ErrInvalid, StageInput, ReasonRecordSet)
	}
	kind := AttemptSuccessor
	if snapshot.PublicationSeq == 0 {
		kind = AttemptGenesis
	}
	return validatedCandidate{kind: kind, id: snapshot.PublicationID, sequence: snapshot.PublicationSeq, key: key, snapshot: snapshot, head: head, snapshotCID: bytes.Clone(snapshotCID), headCID: bytes.Clone(headCID), blobCID: bytes.Clone(snapshot.Blob.CID), payload: bytes.Clone(input.Payload), snapshotRaw: bytes.Clone(input.SnapshotRecord), headRaw: bytes.Clone(input.HeadRecord)}, nil
}

func (s *Store) validateAttemptInput(ctx context.Context, input CandidateInput, viewInput SuppliedRepositoryView, review LocalReviewContext, state stateSnapshot, stage Stage) (validatedCandidate, error) {
	if review.SelectionRevision == 0 || review.ApprovalRevision == 0 || allZero(review.SelectionDigest[:]) || allZero(review.ApprovalDigest[:]) {
		return validatedCandidate{}, classified(ErrInvalid, stage, ReasonContext)
	}
	view, err := validateSuppliedRepositoryView(viewInput, s.binding, s.limits, false)
	if err != nil {
		return validatedCandidate{}, err
	}
	candidate, err := validateCandidateInput(input, s.binding)
	if err != nil {
		return validatedCandidate{}, err
	}
	candidate.view = view
	if candidate.sequence >= ordinaryPublicationLimit {
		return validatedCandidate{}, classified(ErrLimit, stage, ReasonCapacity)
	}
	if candidate.kind == AttemptGenesis {
		if state.floor != nil || !view.empty {
			return validatedCandidate{}, classified(ErrContinuity, stage, ReasonFirstUseRequired)
		}
	} else {
		if state.floor == nil || candidate.sequence != state.floor.Sequence+1 || !bytes.Equal(candidate.snapshot.Parent, state.floor.RecordCID) {
			return validatedCandidate{}, classified(ErrContinuity, stage, ReasonMissingLineage)
		}
		predecessor, err := s.loadRecordByCID(ctx, s.conn, state.floor.RecordCID, state.floor.SnapshotKey, state.floor.Sequence, stage)
		if err != nil {
			return validatedCandidate{}, err
		}
		if err := publication.VerifySuccessor(predecessor.raw, input.SnapshotRecord, input.SnapshotKey); err != nil {
			return validatedCandidate{}, classified(ErrInvalid, stage, ReasonRecordSet)
		}
		candidate.predecessor = &predecessor
		observed, ok := view.byCID[string(state.floor.RecordCID)]
		if !ok || !bytes.Equal(observed.raw, predecessor.raw) || view.empty || view.head.PublicationSeq != state.floor.Sequence || !bytes.Equal(view.head.SnapshotCID, state.floor.RecordCID) {
			return validatedCandidate{}, classified(ErrContinuity, stage, ReasonMissingLineage)
		}
		if _, exists := view.byKey[candidate.key]; exists {
			return validatedCandidate{}, classified(ErrContinuity, stage, ReasonFork)
		}
	}
	if candidate.kind == AttemptGenesis && candidate.sequence != 0 || candidate.kind == AttemptSuccessor && candidate.sequence == 0 {
		return validatedCandidate{}, classified(ErrInvalid, stage, ReasonRecordSet)
	}
	futureCount := uint64(len(view.blocks)) + 1
	if uint64(len(view.blocks)) > uint64(s.limits.MaxLineageLinks) {
		return validatedCandidate{}, classified(ErrLimit, stage, ReasonCapacity)
	}
	if futureCount > uint64(s.limits.SuppliedSnapshotCount) || futureCount > 4095 {
		return validatedCandidate{}, classified(ErrLimit, stage, ReasonCapacity)
	}
	futureBytes := uint64(len(candidate.snapshotRaw) + len(candidate.headRaw))
	for _, record := range view.blocks {
		futureBytes += uint64(len(record.raw))
	}
	if futureBytes > s.limits.SuppliedTotalBytes || futureBytes > 8<<20 {
		return validatedCandidate{}, classified(ErrLimit, stage, ReasonCapacity)
	}
	return candidate, nil
}

func checkedAttemptAdd(left, right uint64) (uint64, bool) {
	if ^uint64(0)-left < right {
		return 0, false
	}
	return left + right, true
}

func (s *Store) checkAttemptAdmissionFeasibility(candidate validatedCandidate, stage Stage) error {
	contextBytes, err := canonicalJSON(contextToWire(candidate.view.input.SuppliedContext))
	if err != nil || uint64(len(contextBytes)) > uint64(s.limits.SuppliedContextBytes) {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	contextExpansion := uint64(s.limits.SuppliedContextBytes) - uint64(len(contextBytes))
	submission, err := encodeAttemptEvidence(attemptEvidenceWire{Version: 1, Role: "submission", Scope: string(candidate.view.input.Scope), ViewDigest: bytes.Clone(candidate.view.digest[:]), Origin: bindingToWire(candidate.view.input.Origin), Context: contextToWire(candidate.view.input.SuppliedContext), Head: bytes.Clone(candidate.view.input.Head), AttemptedKey: candidate.key, AttemptedRecord: bytes.Clone(candidate.snapshotRaw), PredecessorRecord: candidatePredecessorRaw(candidate), Outcome: string(OutcomeUnresolved)})
	if err != nil {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	maxSubmissionBytes, ok := checkedAttemptAdd(uint64(len(submission)), contextExpansion)
	if !ok || maxSubmissionBytes > s.attemptLimits.EventBytes || maxSubmissionBytes > uint64(^uint(0)>>1) {
		return classified(ErrLimit, stage, ReasonCapacity)
	}
	var stateDigest [32]byte
	previousDigest := make([]byte, 32)
	eventBody, eventDigest, err := makeAttemptEvent(candidate.id, s.attemptLimits.LifecycleEvents, maximumAttemptEventKind(), previousDigest, make([]byte, int(maxSubmissionBytes)), stateDigest)
	if err != nil {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	eventBytes, ok := checkedAttemptAdd(uint64(len(eventBody)), uint64(len(eventDigest)))
	if !ok || eventBytes > s.attemptLimits.EventBytes {
		return classified(ErrLimit, stage, ReasonCapacity)
	}
	currentViewInput := cloneSuppliedView(candidate.view.input)
	currentViewInput.Snapshots = append(currentViewInput.Snapshots, SnapshotBlock{Key: candidate.key, Raw: bytes.Clone(candidate.snapshotRaw)})
	currentViewInput.Head = bytes.Clone(candidate.headRaw)
	currentView, err := validateSuppliedRepositoryView(currentViewInput, s.binding, s.limits, false)
	if err != nil {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	proof, err := encodeAttemptEvidence(attemptEvidenceWire{Version: 1, Role: "retirement", Scope: string(currentView.input.Scope), ViewDigest: bytes.Clone(currentView.digest[:]), Origin: bindingToWire(currentView.input.Origin), Context: contextToWire(currentView.input.SuppliedContext), Head: bytes.Clone(currentView.input.Head), AttemptedKey: candidate.key, AttemptedRecord: bytes.Clone(candidate.snapshotRaw), PredecessorRecord: candidatePredecessorRaw(candidate), Suffix: []SnapshotBlock{{Key: candidate.key, Raw: bytes.Clone(candidate.snapshotRaw)}}, Outcome: string(OutcomeCurrent)})
	if err != nil {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	maxProofBytes, ok := checkedAttemptAdd(uint64(len(proof)), contextExpansion)
	if !ok || maxProofBytes > s.attemptLimits.EvidenceSlotBytes {
		return classified(ErrLimit, stage, ReasonCapacity)
	}
	if err := s.checkFirstConflictSlotFeasibility(candidate, contextExpansion, stage); err != nil {
		return err
	}
	return nil
}

func (s *Store) checkFirstConflictSlotFeasibility(candidate validatedCandidate, contextExpansion uint64, stage Stage) error {
	occupant := candidate.snapshot
	occupant.Blob.Size = publication.MaxBlobBytes
	occupant.PublicationID[15] ^= 1
	if allZero(occupant.PublicationID[:]) {
		occupant.PublicationID[0] = 1
	}
	occupantRaw, err := publication.EncodeSnapshot(occupant)
	if err != nil {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	occupantCID, err := publication.RecordCID(occupantRaw)
	if err != nil {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	head, err := publication.EncodeHead(publication.HeadRecord{SchemaVersion: publication.SchemaVersion, Vault: occupant.Vault, PublicationSeq: occupant.PublicationSeq, SnapshotCID: occupantCID, BlobCID: bytes.Clone(occupant.Blob.CID)})
	if err != nil {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	proof := attemptEvidenceWire{Version: 1, Role: "outcome", Scope: string(candidate.view.input.Scope), ViewDigest: make([]byte, 32), Origin: bindingToWire(candidate.view.input.Origin), Context: contextToWire(candidate.view.input.SuppliedContext), Head: head, AttemptedKey: candidate.key, AttemptedRecord: occupantRaw, PredecessorRecord: candidatePredecessorRaw(candidate), Suffix: []SnapshotBlock{{Key: candidate.key, Raw: occupantRaw}}, Outcome: string(OutcomeLostFence)}
	wire := firstConflictWire{Version: 1, AttemptID: bytes.Clone(candidate.id[:]), CoreDigest: make([]byte, 32), EventOrdinal: s.attemptLimits.LifecycleEvents, MutationRevision: ^uint64(0) >> 1, EventStateDigest: make([]byte, 32), Blocked: "blocked-floor-replaced", Proof: proof}
	encoded, err := canonicalJSON(wire)
	if err != nil {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	maximum, ok := checkedAttemptAdd(uint64(len(encoded)), contextExpansion)
	if !ok || maximum > s.attemptLimits.EvidenceSlotBytes {
		return classified(ErrLimit, stage, ReasonCapacity)
	}
	return nil
}

func candidatePredecessorRaw(candidate validatedCandidate) []byte {
	if candidate.predecessor == nil {
		return nil
	}
	return bytes.Clone(candidate.predecessor.raw)
}

func (s *Store) checkFinalizationFeasibility(ctx context.Context, candidate validatedCandidate, state stateSnapshot, stage Stage) error {
	finalContext := cloneContext(candidate.view.input.SuppliedContext)
	encodedContext, err := canonicalJSON(contextToWire(finalContext))
	if err != nil || uint64(len(encodedContext)) > uint64(s.limits.SuppliedContextBytes) {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	contextExpansion := uint64(s.limits.SuppliedContextBytes) - uint64(len(encodedContext))
	next := Floor{DatabaseID: s.databaseID, Revision: state.revision + 1, Generation: state.generation, Provenance: ProvenanceFirst, Binding: s.binding, SuppliedContext: finalContext, Head: bytes.Clone(candidate.headRaw), SnapshotKey: candidate.key, Sequence: candidate.sequence, PublicationID: candidate.id, RecordCID: bytes.Clone(candidate.snapshotCID), BlobCID: bytes.Clone(candidate.blobCID), BlobSize: candidate.snapshot.Blob.Size, ObservationDigest: [32]byte{1}}
	if state.floor == nil {
		next.Generation = 1
	} else {
		next.Provenance = state.floor.Provenance
		next.AnchorCID = bytes.Clone(state.floor.AnchorCID)
	}
	refs := []RecordReference{{Key: candidate.key, CID: bytes.Clone(candidate.snapshotCID), Sequence: candidate.sequence}}
	records := []validatedRecord{{ref: refs[0], raw: candidateSnapshotRaw(candidate)}}
	var oldEncoded []byte
	if state.floor != nil {
		old := cloneFloor(*state.floor)
		oldEncoded, err = encodeFloor(old)
		if err != nil {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
		next.Provenance = old.Provenance
		refs = append(refs, RecordReference{Key: old.SnapshotKey, CID: bytes.Clone(old.RecordCID), Sequence: old.Sequence})
		if candidate.predecessor == nil {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
		records = append(records, cloneValidatedRecord(*candidate.predecessor))
		next.AnchorCID = bytes.Clone(old.AnchorCID)
	} else {
		next.AnchorCID = bytes.Clone(candidate.snapshotCID)
	}
	next.ObservationDigest = [32]byte{1}
	var setDigest [32]byte
	setDigest[0] = 1
	mode := ModeAdvance
	stop := "joined"
	body, err := makeEventBody(mode, "", state.floor, next, refs, stop, next.ObservationDigest, setDigest)
	if state.floor == nil {
		mode = ModeFirstUse
		stop = "first_use"
		body, err = makeEventBody(mode, "", nil, next, refs[:1], stop, next.ObservationDigest, setDigest)
	}
	if err != nil {
		return classified(ErrInvalid, stage, ReasonRecordSet)
	}
	eventDigest := domainHash("systems.lamb.dottie.local-publication-event.v1", body)
	next.AcceptedEventDigest = eventDigest
	newEncoded, err := encodeFloor(next)
	if err != nil {
		return classified(ErrInvalid, stage, ReasonRecordSet)
	}
	eventLogical := eventLogicalBytes(body, eventDigest[:], oldEncoded, newEncoded, string(mode), "", stop)
	eventBytes := uint64(len(body) + 32 + 8)
	seen := map[string]bool{}
	for _, record := range records {
		if !seen[string(record.ref.CID)] {
			seen[string(record.ref.CID)] = true
			eventBytes += recordLogicalBytes(record)
		}
	}
	if state.floor != nil {
		if _, ok := seen[string(state.floor.RecordCID)]; !ok {
			anchor, loadErr := s.loadRecordByCID(ctx, s.conn, state.floor.RecordCID, state.floor.SnapshotKey, state.floor.Sequence, stage)
			if loadErr != nil {
				return loadErr
			}
			eventBytes += recordLogicalBytes(anchor)
		}
	}
	if ^uint64(0)-eventBytes < contextExpansion || ^uint64(0)-eventLogical < 2*contextExpansion {
		return classified(ErrLimit, stage, ReasonCapacity)
	}
	reservedHistoryBytes := eventBytes + contextExpansion
	reservedPrivateBytes := uint64(len(oldEncoded)) + uint64(len(newEncoded)) + uint64(len(body)) + 2*contextExpansion
	reservedEventLogicalBytes := eventLogical + 2*contextExpansion
	if reservedHistoryBytes > s.limits.HistoryEvidenceBytes || reservedPrivateBytes > 65536 {
		return classified(ErrLimit, stage, ReasonCapacity)
	}
	return s.checkAttemptCompletionCapacity(ctx, s.conn, records, reservedEventLogicalBytes, stage)
}

func candidateSnapshotRaw(candidate validatedCandidate) []byte {
	return bytes.Clone(candidate.snapshotRaw)
}

func cloneSuppliedView(view SuppliedRepositoryView) SuppliedRepositoryView {
	out := SuppliedRepositoryView{Origin: view.Origin, Scope: view.Scope, SuppliedContext: cloneContext(view.SuppliedContext), Head: bytes.Clone(view.Head), Snapshots: cloneSnapshotBlocks(view.Snapshots)}
	return out
}

func cloneSnapshotBlocks(blocks []SnapshotBlock) []SnapshotBlock {
	out := make([]SnapshotBlock, len(blocks))
	for index, block := range blocks {
		out[index] = SnapshotBlock{Key: block.Key, Raw: bytes.Clone(block.Raw)}
	}
	return out
}

func attemptPayloadReference(candidate validatedCandidate) publication.BlobReference {
	return publication.BlobReference{CID: bytes.Clone(candidate.blobCID), Size: candidate.snapshot.Blob.Size}
}

func validLifecycle(value AttemptLifecycle) bool {
	switch value {
	case AttemptPrepared, AttemptUploadStarted, AttemptMayHaveSubmitted, AttemptRetiredSuccess, AttemptRetiredAbandoned:
		return true
	default:
		return false
	}
}

func validOutcome(value AttemptOutcome) bool {
	switch value {
	case OutcomeNotSubmitted, OutcomeUnresolved, OutcomeAbsentUnresolved, OutcomeCurrent, OutcomeSuperseded, OutcomeLostFence:
		return true
	default:
		return false
	}
}
