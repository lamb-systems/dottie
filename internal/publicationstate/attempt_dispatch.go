package publicationstate

import (
	"bytes"
	"context"
	"database/sql"

	"github.com/lamb-systems/dottie/internal/publication"
)

func (s *Store) PrepareDispatch(ctx context.Context, id [16]byte, kind DispatchKind, view SuppliedRepositoryView, review LocalReviewContext) (DispatchProposal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkContext(ctx, StageDispatch); err != nil {
		return DispatchProposal{}, err
	}
	if err := s.requireReadback(StageDispatch); err != nil {
		return DispatchProposal{}, err
	}
	state, err := s.readState(ctx, s.conn, StageDispatch)
	if err != nil {
		return DispatchProposal{}, err
	}
	stored, err := s.loadStoredAttempt(ctx, s.conn, id, StageDispatch)
	if err != nil {
		return DispatchProposal{}, err
	}
	if err := s.validateDispatchReview(ctx, s.conn, stored, kind, view, review, state, StageDispatch); err != nil {
		return DispatchProposal{}, err
	}
	token, err := s.currentToken(ctx, s.conn, state, StageDispatch)
	if err != nil {
		return DispatchProposal{}, err
	}
	validatedView, err := validateSuppliedRepositoryView(view, s.binding, s.limits, stored.core.Kind == string(AttemptGenesis))
	if err != nil {
		return DispatchProposal{}, err
	}
	if _, err := s.readCandidateUnlocked(ctx, stored, StageDispatch); err != nil {
		return DispatchProposal{}, err
	}
	confirmation, err := makeDispatchConfirmation(s.databaseID, token, id, kind, validatedView.digest, review)
	if err != nil {
		return DispatchProposal{}, classified(ErrInvalid, StageDispatch, ReasonRecordSet)
	}
	return DispatchProposal{AttemptID: id, Kind: kind, StateToken: token, Confirmation: confirmation}, nil
}

func (s *Store) BeginUpload(ctx context.Context, id [16]byte, expectedToken [32]byte, view SuppliedRepositoryView, review LocalReviewContext, confirmation [32]byte) (UploadMaterial, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkContext(ctx, StageDispatch); err != nil {
		return UploadMaterial{}, err
	}
	if err := s.requireReadback(StageDispatch); err != nil {
		return UploadMaterial{}, err
	}
	state, err := s.readState(ctx, s.conn, StageDispatch)
	if err != nil {
		return UploadMaterial{}, err
	}
	stored, err := s.loadStoredAttempt(ctx, s.conn, id, StageDispatch)
	if err != nil {
		return UploadMaterial{}, err
	}
	if err := s.validateDispatchReview(ctx, s.conn, stored, DispatchUpload, view, review, state, StageDispatch); err != nil {
		return UploadMaterial{}, err
	}
	viewState, err := validateSuppliedRepositoryView(view, s.binding, s.limits, stored.core.Kind == string(AttemptGenesis))
	if err != nil {
		return UploadMaterial{}, err
	}
	token, err := s.currentToken(ctx, s.conn, state, StageDispatch)
	if err != nil || !bytes.Equal(token[:], expectedToken[:]) {
		return UploadMaterial{}, classified(ErrConsent, StageDispatch, ReasonStale)
	}
	wantConfirmation, err := makeDispatchConfirmation(s.databaseID, token, id, DispatchUpload, viewState.digest, review)
	if err != nil || !bytes.Equal(wantConfirmation[:], confirmation[:]) {
		return UploadMaterial{}, classified(ErrConsent, StageDispatch, ReasonConfirmation)
	}
	candidate, err := s.readCandidateUnlocked(ctx, stored, StageDispatch)
	if err != nil {
		return UploadMaterial{}, err
	}
	if err := s.preflightSidecars(); err != nil {
		return UploadMaterial{}, storageFailure(ctx, StageDispatch, err)
	}
	var nextMutation uint64
	err = s.withTx(ctx, StageDispatch, func(tx *sql.Tx) error {
		fresh, err := s.loadStoredAttempt(ctx, tx, id, StageDispatch)
		if err != nil {
			return err
		}
		state, err := s.readState(ctx, tx, StageDispatch)
		if err != nil {
			return err
		}
		freshToken, err := s.currentToken(ctx, tx, state, StageDispatch)
		if err != nil || !bytes.Equal(freshToken[:], expectedToken[:]) {
			return classified(ErrConsent, StageDispatch, ReasonStale)
		}
		lifecycle := AttemptUploadStarted
		event := ""
		if fresh.lifecycle == AttemptPrepared {
			event = "upload-started"
		} else if fresh.lifecycle != AttemptUploadStarted {
			return classified(ErrConsent, StageDispatch, ReasonTransition)
		}
		nextMutation, err = s.updateAttemptTx(ctx, tx, fresh, lifecycle, OutcomeNotSubmitted, fresh.blocked, "", nil, nil, event, nil, nil, StageDispatch)
		return err
	})
	if err != nil {
		return UploadMaterial{}, err
	}
	s.attemptMutationRevision = nextMutation
	return UploadMaterial{AttemptID: id, Payload: bytes.Clone(candidate.Payload), Blob: publication.BlobReference{CID: bytes.Clone(stored.core.BlobCID), Size: stored.core.BlobSize}}, nil
}

func (s *Store) BeginSubmission(ctx context.Context, id [16]byte, expectedToken [32]byte, view SuppliedRepositoryView, review LocalReviewContext, confirmation [32]byte) (SubmissionMaterial, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkContext(ctx, StageDispatch); err != nil {
		return SubmissionMaterial{}, err
	}
	if err := s.requireReadback(StageDispatch); err != nil {
		return SubmissionMaterial{}, err
	}
	state, err := s.readState(ctx, s.conn, StageDispatch)
	if err != nil {
		return SubmissionMaterial{}, err
	}
	stored, err := s.loadStoredAttempt(ctx, s.conn, id, StageDispatch)
	if err != nil {
		return SubmissionMaterial{}, err
	}
	if err := s.validateDispatchReview(ctx, s.conn, stored, DispatchSubmission, view, review, state, StageDispatch); err != nil {
		return SubmissionMaterial{}, err
	}
	validatedView, err := validateSuppliedRepositoryView(view, s.binding, s.limits, stored.core.Kind == string(AttemptGenesis))
	if err != nil {
		return SubmissionMaterial{}, err
	}
	token, err := s.currentToken(ctx, s.conn, state, StageDispatch)
	if err != nil || !bytes.Equal(token[:], expectedToken[:]) {
		return SubmissionMaterial{}, classified(ErrConsent, StageDispatch, ReasonStale)
	}
	wantConfirmation, err := makeDispatchConfirmation(s.databaseID, token, id, DispatchSubmission, validatedView.digest, review)
	if err != nil || !bytes.Equal(wantConfirmation[:], confirmation[:]) {
		return SubmissionMaterial{}, classified(ErrConsent, StageDispatch, ReasonConfirmation)
	}
	if stored.lifecycle != AttemptUploadStarted || stored.blocked != "" {
		return SubmissionMaterial{}, classified(ErrConsent, StageDispatch, ReasonTransition)
	}
	candidate, err := s.readCandidateUnlocked(ctx, stored, StageDispatch)
	if err != nil {
		return SubmissionMaterial{}, err
	}
	if err := s.preflightSidecars(); err != nil {
		return SubmissionMaterial{}, storageFailure(ctx, StageDispatch, err)
	}
	boundaryEvidence, err := encodeAttemptEvidence(attemptEvidenceWire{Version: 1, Role: "submission", Scope: string(view.Scope), ViewDigest: bytes.Clone(validatedView.digest[:]), Origin: bindingToWire(view.Origin), Context: contextToWire(view.SuppliedContext), Head: bytes.Clone(view.Head), AttemptedKey: stored.core.SnapshotKey, AttemptedRecord: bytes.Clone(stored.core.SnapshotRecord), PredecessorRecord: bytes.Clone(stored.core.PredecessorRecord), Outcome: string(OutcomeUnresolved)})
	if err != nil || uint64(len(boundaryEvidence)) > s.attemptLimits.EventBytes {
		return SubmissionMaterial{}, classified(ErrLimit, StageDispatch, ReasonCapacity)
	}
	var nextMutation uint64
	err = s.withTx(ctx, StageDispatch, func(tx *sql.Tx) error {
		fresh, err := s.loadStoredAttempt(ctx, tx, id, StageDispatch)
		if err != nil {
			return err
		}
		state, err := s.readState(ctx, tx, StageDispatch)
		if err != nil {
			return err
		}
		freshToken, err := s.currentToken(ctx, tx, state, StageDispatch)
		if err != nil || !bytes.Equal(freshToken[:], expectedToken[:]) {
			return classified(ErrConsent, StageDispatch, ReasonStale)
		}
		if fresh.lifecycle != AttemptUploadStarted || fresh.blocked != "" {
			return classified(ErrConsent, StageDispatch, ReasonTransition)
		}
		nextMutation, err = s.updateAttemptTx(ctx, tx, fresh, AttemptMayHaveSubmitted, OutcomeUnresolved, "", "", nil, nil, "may-have-submitted", boundaryEvidence, nil, StageDispatch)
		return err
	})
	if err != nil {
		return SubmissionMaterial{}, err
	}
	s.attemptMutationRevision = nextMutation
	material := SubmissionMaterial{AttemptID: id, SnapshotCollection: publication.SnapshotNSID, SnapshotKey: stored.core.SnapshotKey, SnapshotRecord: bytes.Clone(candidate.SnapshotRecord), ExpectedSnapshotCID: bytes.Clone(stored.core.SnapshotCID), SnapshotCreateOnly: true, HeadCollection: publication.HeadNSID, HeadKey: "self", HeadRecord: bytes.Clone(candidate.HeadRecord), HeadCreate: stored.core.Kind == string(AttemptGenesis), ExpectedContext: cloneContext(view.SuppliedContext), RequiresAtomicBatch: true, RequiresCreateExclude: true, RequiresPolicyCheck: s.binding.Backend == BackendSpaces}
	if len(stored.core.PredecessorCID) > 0 {
		material.ExpectedPredecessor = &RecordReference{Key: stored.core.PredecessorKey, CID: bytes.Clone(stored.core.PredecessorCID), Sequence: stored.core.CapturedFloor.Sequence}
	}
	return material, nil
}

func (s *Store) validateDispatchReview(ctx context.Context, q queryer, stored storedAttempt, kind DispatchKind, input SuppliedRepositoryView, review LocalReviewContext, state stateSnapshot, stage Stage) error {
	if kind != DispatchUpload && kind != DispatchSubmission {
		return classified(ErrInvalid, stage, ReasonMode)
	}
	if stored.blocked != "" {
		return classified(ErrContinuity, stage, ReasonFloorReplaced)
	}
	if stored.lifecycle == AttemptMayHaveSubmitted || stored.lifecycle == AttemptRetiredSuccess || stored.lifecycle == AttemptRetiredAbandoned {
		return classified(ErrConsent, stage, ReasonTransition)
	}
	if kind == DispatchSubmission && stored.lifecycle != AttemptUploadStarted {
		return classified(ErrConsent, stage, ReasonTransition)
	}
	if kind == DispatchUpload && stored.lifecycle != AttemptPrepared && stored.lifecycle != AttemptUploadStarted {
		return classified(ErrConsent, stage, ReasonTransition)
	}
	if !reviewMatches(stored.core.Review, review) {
		return classified(ErrConsent, stage, ReasonStale)
	}
	if state.revision != stored.core.CapturedRevision || state.generation != stored.core.CapturedGeneration || !sameCapturedFloor(stored.core.CapturedFloor, state.floor) {
		return classified(ErrContinuity, stage, ReasonStale)
	}
	view, err := validateSuppliedRepositoryView(input, s.binding, s.limits, false)
	if err != nil {
		return err
	}
	initialContext, err := contextFromWire(stored.core.InitialContext)
	if err != nil {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	if !samePolicy(initialContext.Policy, input.SuppliedContext.Policy) {
		return classified(ErrContinuity, stage, ReasonContext)
	}
	if stored.core.Kind == string(AttemptGenesis) {
		if !view.empty {
			return classified(ErrContinuity, stage, ReasonFork)
		}
	} else {
		floor, err := floorFromWire(*stored.core.CapturedFloor)
		if err != nil {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
		predecessor, ok := view.byCID[string(floor.RecordCID)]
		if !ok || !bytes.Equal(predecessor.raw, stored.core.PredecessorRecord) || view.head.PublicationSeq != floor.Sequence || !bytes.Equal(view.head.SnapshotCID, floor.RecordCID) {
			return classified(ErrContinuity, stage, ReasonMissingLineage)
		}
		if _, exists := view.byKey[stored.core.SnapshotKey]; exists {
			return classified(ErrContinuity, stage, ReasonFork)
		}
	}
	return nil
}

func reviewMatches(wire localReviewWire, review LocalReviewContext) bool {
	return len(wire.SelectionDigest) == 32 && len(wire.ApprovalDigest) == 32 && bytes.Equal(wire.SelectionDigest, review.SelectionDigest[:]) && wire.SelectionRevision == review.SelectionRevision && bytes.Equal(wire.ApprovalDigest, review.ApprovalDigest[:]) && wire.ApprovalRevision == review.ApprovalRevision
}

func sameCapturedFloor(wire *floorWire, floor *Floor) bool {
	if wire == nil || floor == nil {
		return wire == nil && floor == nil
	}
	encoded, err := canonicalJSON(wire)
	if err != nil {
		return false
	}
	current, err := encodeFloor(*floor)
	if err != nil {
		return false
	}
	return bytes.Equal(encoded, current)
}

func samePolicy(left, right *Policy) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Revision == right.Revision && left.OwnerOnly == right.OwnerOnly && bytes.Equal(left.Identity, right.Identity)
}

func (s *Store) readCandidateUnlocked(ctx context.Context, stored storedAttempt, stage Stage) (CandidateMaterial, error) {
	if err := s.openPayloadDirectoryForRead(); err != nil {
		return CandidateMaterial{}, classifyCandidateDirectory(err, stage)
	}
	var basename string
	var sizeValue any
	if err := s.conn.QueryRowContext(ctx, "SELECT payload_objects.basename,payload_objects.size FROM attempt_payload_refs JOIN payload_objects USING(blob_cid) WHERE attempt_payload_refs.attempt_id=?", stored.core.AttemptID).Scan(&basename, &sizeValue); err != nil {
		return CandidateMaterial{}, classified(ErrSchema, stage, ReasonCorrupt)
	}
	size, ok := rawInt64(sizeValue)
	if !ok || size <= 0 || uint64(size) != stored.core.BlobSize {
		return CandidateMaterial{}, classified(ErrSchema, stage, ReasonCorrupt)
	}
	blob := publication.BlobReference{CID: bytes.Clone(stored.core.BlobCID), Size: stored.core.BlobSize}
	payload, err := s.inspectPayloadFile(basename, nil, blob)
	if err != nil {
		return CandidateMaterial{}, classifyCandidateRead(err, stage)
	}
	var id [16]byte
	copy(id[:], stored.core.AttemptID)
	return CandidateMaterial{AttemptID: id, SnapshotKey: stored.core.SnapshotKey, SnapshotRecord: bytes.Clone(stored.core.SnapshotRecord), HeadRecord: bytes.Clone(stored.core.HeadRecord), Payload: payload, Blob: blob}, nil
}
