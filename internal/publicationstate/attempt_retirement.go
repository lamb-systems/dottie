package publicationstate

import (
	"bytes"
	"context"
	"database/sql"
)

type abandonConfirmationWire struct {
	Version           uint32     `json:"version"`
	DatabaseID        []byte     `json:"databaseId"`
	MutationToken     []byte     `json:"mutationToken"`
	AttemptID         []byte     `json:"attemptId"`
	CandidateDigest   []byte     `json:"candidateDigest"`
	Floor             *floorWire `json:"floor"`
	Lifecycle         string     `json:"lifecycle"`
	Outcome           string     `json:"outcome"`
	Blocked           string     `json:"blocked"`
	Evidence          []byte     `json:"evidence"`
	ReferenceReleased bool       `json:"referenceReleased"`
	Warning           string     `json:"warning"`
}

func (s *Store) PrepareAbandon(ctx context.Context, id [16]byte, input *SuppliedRepositoryView) (AbandonProposal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkContext(ctx, StageAbandon); err != nil {
		return AbandonProposal{}, err
	}
	if err := s.requireReadback(StageAbandon); err != nil {
		return AbandonProposal{}, err
	}
	state, err := s.readState(ctx, s.conn, StageAbandon)
	if err != nil {
		return AbandonProposal{}, err
	}
	stored, err := s.loadStoredAttempt(ctx, s.conn, id, StageAbandon)
	if err != nil {
		return AbandonProposal{}, err
	}
	if stored.lifecycle == AttemptRetiredAbandoned || stored.lifecycle == AttemptRetiredSuccess {
		return AbandonProposal{}, classified(ErrConsent, StageAbandon, ReasonTransition)
	}
	outcome, evidence, err := s.abandonEligibility(stored, input)
	if err != nil {
		return AbandonProposal{}, err
	}
	token, err := s.currentToken(ctx, s.conn, state, StageAbandon)
	if err != nil {
		return AbandonProposal{}, err
	}
	confirmation, err := s.makeAbandonConfirmation(stored, state, token, outcome, evidence)
	if err != nil {
		return AbandonProposal{}, classified(ErrInvalid, StageAbandon, ReasonRecordSet)
	}
	return AbandonProposal{AttemptID: id, StateToken: token, Confirmation: confirmation, Warning: AbandonWarning}, nil
}

func (s *Store) AbandonAttempt(ctx context.Context, id [16]byte, expectedToken [32]byte, input *SuppliedRepositoryView, confirmation [32]byte) (Attempt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkContext(ctx, StageAbandon); err != nil {
		return Attempt{}, err
	}
	if err := s.requireReadback(StageAbandon); err != nil {
		return Attempt{}, err
	}
	state, err := s.readState(ctx, s.conn, StageAbandon)
	if err != nil {
		return Attempt{}, err
	}
	stored, err := s.loadStoredAttempt(ctx, s.conn, id, StageAbandon)
	if err != nil {
		return Attempt{}, err
	}
	if stored.lifecycle == AttemptRetiredAbandoned || stored.lifecycle == AttemptRetiredSuccess {
		return Attempt{}, classified(ErrConsent, StageAbandon, ReasonTransition)
	}
	outcome, evidence, err := s.abandonEligibility(stored, input)
	if err != nil {
		return Attempt{}, err
	}
	token, err := s.currentToken(ctx, s.conn, state, StageAbandon)
	if err != nil || !bytes.Equal(token[:], expectedToken[:]) {
		return Attempt{}, classified(ErrConsent, StageAbandon, ReasonStale)
	}
	want, err := s.makeAbandonConfirmation(stored, state, token, outcome, evidence)
	if err != nil || !bytes.Equal(want[:], confirmation[:]) {
		return Attempt{}, classified(ErrConsent, StageAbandon, ReasonConfirmation)
	}
	if err := s.preflightSidecars(); err != nil {
		return Attempt{}, storageFailure(ctx, StageAbandon, err)
	}
	var nextMutation uint64
	var retiredAttempt Attempt
	err = s.withTx(ctx, StageAbandon, func(tx *sql.Tx) error {
		fresh, err := s.loadStoredAttempt(ctx, tx, id, StageAbandon)
		if err != nil {
			return err
		}
		freshState, err := s.readState(ctx, tx, StageAbandon)
		if err != nil {
			return err
		}
		freshToken, err := s.currentToken(ctx, tx, freshState, StageAbandon)
		if err != nil || !bytes.Equal(freshToken[:], expectedToken[:]) {
			return classified(ErrConsent, StageAbandon, ReasonStale)
		}
		freshOutcome, freshEvidence, err := s.abandonEligibility(fresh, input)
		if err != nil {
			return err
		}
		freshConfirmation, err := s.makeAbandonConfirmation(fresh, freshState, freshToken, freshOutcome, freshEvidence)
		if err != nil || !bytes.Equal(freshConfirmation[:], confirmation[:]) {
			return classified(ErrConsent, StageAbandon, ReasonConfirmation)
		}
		retirement := freshEvidence
		if retirement == nil {
			retirement, err = encodeAttemptEvidence(attemptEvidenceWire{Version: 1, Role: "retirement", AttemptedKey: fresh.core.SnapshotKey, AttemptedRecord: bytes.Clone(fresh.core.SnapshotRecord), Outcome: string(freshOutcome)})
			if err != nil {
				return classified(ErrInvalid, StageAbandon, ReasonRecordSet)
			}
		}
		if freshEvidence != nil {
			outcomeEvent := ""
			if freshOutcome != fresh.outcome {
				outcomeEvent = "outcome-" + string(freshOutcome)
			}
			var outcomeDigest [32]byte
			var mutation uint64
			if freshOutcome == OutcomeLostFence && !terminalOutcome(fresh.outcome) {
				mutation, err = s.updateAttemptTxWithFirstConflict(ctx, tx, fresh, fresh.lifecycle, freshOutcome, fresh.blocked, "outcome", freshEvidence, nil, outcomeEvent, nil, freshEvidence, &outcomeDigest, StageAbandon)
			} else {
				mutation, err = s.updateAttemptTx(ctx, tx, fresh, fresh.lifecycle, freshOutcome, fresh.blocked, "outcome", freshEvidence, nil, outcomeEvent, nil, &outcomeDigest, StageAbandon)
			}
			if err != nil {
				return err
			}
			fresh.outcome = freshOutcome
			fresh.mutationRevision = mutation
			fresh.stateDigest = bytes.Clone(outcomeDigest[:])
			fresh.terminal = bytes.Clone(freshEvidence)
		}
		var newStateDigest [32]byte
		nextMutation, err = s.updateAttemptTx(ctx, tx, fresh, AttemptRetiredAbandoned, freshOutcome, fresh.blocked, "retirement", retirement, retirement, "retired-abandoned", nil, &newStateDigest, StageAbandon)
		if err != nil {
			return err
		}
		retiredAttempt = projectAttempt(fresh.core, AttemptRetiredAbandoned, freshOutcome, fresh.blocked, nextMutation, AvailabilityUnchecked)
		retiredAttempt.StateDigest = newStateDigest
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{"DELETE FROM attempt_payload_refs WHERE attempt_id=?", []any{id[:]}},
			{"DELETE FROM active_publication_attempt WHERE singleton=1 AND attempt_id=?", []any{id[:]}},
			{"DELETE FROM pending_genesis WHERE attempt_id=?", []any{id[:]}},
			{"DELETE FROM attempt_reservations WHERE attempt_id=?", []any{id[:]}},
		} {
			if _, err := tx.ExecContext(ctx, statement.query, statement.args...); err != nil {
				return classified(ErrStorage, StageAbandon, ReasonIO)
			}
		}
		return nil
	})
	if err != nil {
		return Attempt{}, err
	}
	s.attemptMutationRevision = nextMutation
	return retiredAttempt, nil
}

func (s *Store) abandonEligibility(stored storedAttempt, input *SuppliedRepositoryView) (AttemptOutcome, []byte, error) {
	neverSubmitted := stored.lifecycle == AttemptPrepared || stored.lifecycle == AttemptUploadStarted
	if neverSubmitted {
		if input == nil {
			return OutcomeNotSubmitted, nil, nil
		}
		view, err := validateSuppliedRepositoryView(*input, s.binding, s.limits, stored.core.Kind == string(AttemptGenesis))
		if err != nil {
			return "", nil, err
		}
		if observed, ok := view.byKey[stored.core.SnapshotKey]; ok && bytes.Equal(observed.raw, stored.core.SnapshotRecord) {
			return "", nil, classified(ErrContinuity, StageAbandon, ReasonTransition)
		}
		evidence, err := s.compactAttemptEvidence(stored, view, OutcomeNotSubmitted)
		if err != nil {
			return "", nil, err
		}
		return OutcomeNotSubmitted, evidence, nil
	}
	if stored.lifecycle != AttemptMayHaveSubmitted || input == nil {
		return "", nil, classified(ErrContinuity, StageAbandon, ReasonSubmittedUnknown)
	}
	view, err := validateSuppliedRepositoryView(*input, s.binding, s.limits, stored.core.Kind == string(AttemptGenesis))
	if err != nil {
		return "", nil, err
	}
	if err := s.validateAttemptPolicy(stored.core, view.input.SuppliedContext, StageAbandon); err != nil {
		return "", nil, err
	}
	outcome, evidence, err := s.deriveAttemptOutcome(stored, view)
	if err != nil {
		return "", nil, err
	}
	if !terminalOutcome(outcome) {
		return "", nil, classified(ErrContinuity, StageAbandon, ReasonSubmittedUnknown)
	}
	if err := preserveTerminalOutcome(stored, outcome, evidence); err != nil {
		return "", nil, err
	}
	return outcome, evidence, nil
}

func (s *Store) makeAbandonConfirmation(stored storedAttempt, state stateSnapshot, token [32]byte, outcome AttemptOutcome, evidence []byte) ([32]byte, error) {
	var floor *floorWire
	if state.floor != nil {
		wire := floorToWire(*state.floor)
		floor = &wire
	}
	coreDigest := makeAttemptCoreDigest(stored.coreBytes)
	wire := abandonConfirmationWire{Version: 1, DatabaseID: bytes.Clone(s.databaseID[:]), MutationToken: bytes.Clone(token[:]), AttemptID: bytes.Clone(stored.core.AttemptID), CandidateDigest: bytes.Clone(coreDigest[:]), Floor: floor, Lifecycle: string(stored.lifecycle), Outcome: string(outcome), Blocked: stored.blocked, Evidence: bytes.Clone(evidence), ReferenceReleased: true, Warning: AbandonWarning}
	body, err := canonicalJSON(wire)
	if err != nil {
		return [32]byte{}, err
	}
	return domainHash("systems.lamb.dottie.local-attempt-abandon.v1", body), nil
}

func (s *Store) FinalizeAttempt(ctx context.Context, id [16]byte, expectedToken [32]byte, input SuppliedRepositoryView) (Finalization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkContext(ctx, StageFinalize); err != nil {
		return Finalization{}, err
	}
	if err := s.requireReadback(StageFinalize); err != nil {
		return Finalization{}, err
	}
	state, err := s.readState(ctx, s.conn, StageFinalize)
	if err != nil {
		return Finalization{}, err
	}
	stored, err := s.loadStoredAttempt(ctx, s.conn, id, StageFinalize)
	if err != nil {
		return Finalization{}, err
	}
	if !bytes.Equal(stored.stateDigest, expectedToken[:]) {
		return Finalization{}, classified(ErrConsent, StageFinalize, ReasonStale)
	}
	if stored.lifecycle != AttemptMayHaveSubmitted || stored.blocked != "" {
		return Finalization{}, classified(ErrConsent, StageFinalize, ReasonTransition)
	}
	if state.revision != stored.core.CapturedRevision || state.generation != stored.core.CapturedGeneration || !sameCapturedFloor(stored.core.CapturedFloor, state.floor) {
		return Finalization{}, classified(ErrContinuity, StageFinalize, ReasonStale)
	}
	view, err := validateSuppliedRepositoryView(input, s.binding, s.limits, false)
	if err != nil {
		return Finalization{}, err
	}
	if err := s.validateAttemptPolicy(stored.core, view.input.SuppliedContext, StageFinalize); err != nil {
		return Finalization{}, err
	}
	outcome, evidence, err := s.deriveAttemptOutcome(stored, view)
	if err != nil {
		return Finalization{}, err
	}
	if outcome != OutcomeCurrent {
		return Finalization{}, classified(ErrContinuity, StageFinalize, ReasonSubmittedUnknown)
	}
	if err := preserveTerminalOutcome(stored, outcome, evidence); err != nil {
		return Finalization{}, err
	}
	candidate, err := s.readCandidateUnlocked(ctx, stored, StageFinalize)
	if err != nil {
		return Finalization{}, err
	}
	observation := repositoryViewToObservation(view)
	validated, err := validateObservation(observation, s.binding, s.limits)
	if err != nil {
		return Finalization{}, err
	}
	if !bytes.Equal(validated.candidate.ref.CID, stored.core.SnapshotCID) || !bytes.Equal(validated.candidate.raw, candidate.SnapshotRecord) {
		return Finalization{}, classified(ErrContinuity, StageFinalize, ReasonRecordSet)
	}
	trace, err := s.resolveTrace(ctx, s.conn, validated, state.floor, StageFinalize)
	if err != nil {
		return Finalization{}, err
	}
	mode := ModeAdvance
	if state.floor == nil {
		mode = ModeFirstUse
	}
	if err := s.preflightSidecars(); err != nil {
		return Finalization{}, storageFailure(ctx, StageFinalize, err)
	}
	var floor Floor
	var nextMutation uint64
	var finalizedAttempt Attempt
	err = s.withTx(ctx, StageFinalize, func(tx *sql.Tx) error {
		freshState, err := s.readState(ctx, tx, StageFinalize)
		if err != nil {
			return err
		}
		fresh, err := s.loadStoredAttempt(ctx, tx, id, StageFinalize)
		if err != nil {
			return err
		}
		if !bytes.Equal(fresh.stateDigest, expectedToken[:]) || fresh.lifecycle != AttemptMayHaveSubmitted || fresh.blocked != "" || freshState.revision != stored.core.CapturedRevision || freshState.generation != stored.core.CapturedGeneration || !sameCapturedFloor(stored.core.CapturedFloor, freshState.floor) {
			return classified(ErrConsent, StageFinalize, ReasonStale)
		}
		freshValidatedView, err := validateSuppliedRepositoryView(input, s.binding, s.limits, false)
		if err != nil {
			return err
		}
		if err := s.validateAttemptPolicy(fresh.core, freshValidatedView.input.SuppliedContext, StageFinalize); err != nil {
			return err
		}
		freshOutcome, freshEvidence, err := s.deriveAttemptOutcome(fresh, freshValidatedView)
		if err != nil {
			return err
		}
		if freshOutcome != OutcomeCurrent {
			return classified(ErrContinuity, StageFinalize, ReasonSubmittedUnknown)
		}
		if err := preserveTerminalOutcome(fresh, freshOutcome, freshEvidence); err != nil {
			return err
		}
		floor, err = s.acceptFloorTx(ctx, tx, mode, freshState, validated, trace, StageFinalize, id[:])
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO retained_publications(record_cid,attempt_id,sequence,blob_cid,size,accepted_revision) VALUES(?,?,?,?,?,?)", fresh.core.SnapshotCID, id[:], int64(floor.Sequence), fresh.core.BlobCID, int64(fresh.core.BlobSize), int64(floor.Revision)); err != nil {
			return classified(ErrStorage, StageFinalize, ReasonIO)
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM attempt_payload_refs WHERE attempt_id=?", id[:]); err != nil {
			return classified(ErrStorage, StageFinalize, ReasonIO)
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM active_publication_attempt WHERE singleton=1 AND attempt_id=?", id[:]); err != nil {
			return classified(ErrStorage, StageFinalize, ReasonIO)
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM pending_genesis WHERE attempt_id=?", id[:]); err != nil {
			return classified(ErrStorage, StageFinalize, ReasonIO)
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM attempt_reservations WHERE attempt_id=?", id[:]); err != nil {
			return classified(ErrStorage, StageFinalize, ReasonIO)
		}
		var finalizedStateDigest [32]byte
		retiredMutation, err := s.updateAttemptTx(ctx, tx, fresh, AttemptRetiredSuccess, OutcomeCurrent, "", "outcome", freshEvidence, nil, "retired-success", nil, &finalizedStateDigest, StageFinalize)
		if err != nil {
			return err
		}
		nextMutation = retiredMutation
		finalizedAttempt = projectAttempt(fresh.core, AttemptRetiredSuccess, OutcomeCurrent, "", retiredMutation, AvailabilityAvailable)
		finalizedAttempt.StateDigest = finalizedStateDigest
		return nil
	})
	if err != nil {
		return Finalization{}, err
	}
	s.attemptMutationRevision = nextMutation
	return Finalization{Attempt: finalizedAttempt, Floor: floor}, nil
}

func repositoryViewToObservation(view validatedRepositoryView) Observation {
	blocks := make([]SnapshotBlock, 0, len(view.blocks))
	for _, record := range view.blocks {
		blocks = append(blocks, SnapshotBlock{Key: record.ref.Key, Raw: bytes.Clone(record.raw)})
	}
	return Observation{Origin: view.input.Origin, SuppliedContext: cloneContext(view.input.SuppliedContext), Head: bytes.Clone(view.input.Head), Snapshots: blocks}
}

func (s *Store) attemptReservationSize() uint64 {
	return uint64(s.attemptLimits.CoreBytes) + uint64(s.attemptLimits.LifecycleEvents)*s.attemptLimits.EventBytes + 3*(s.attemptLimits.EvidenceSlotBytes+32)
}
