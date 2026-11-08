package publicationstate

import (
	"bytes"
	"context"
	"database/sql"

	"github.com/lamb-systems/dottie/internal/publication"
)

func (s *Store) ResolveAttempt(ctx context.Context, id [16]byte, expectedToken [32]byte, input SuppliedRepositoryView) (AttemptResolution, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkContext(ctx, StageResolve); err != nil {
		return AttemptResolution{}, err
	}
	if err := s.requireReadback(StageResolve); err != nil {
		return AttemptResolution{}, err
	}
	if _, err := s.readState(ctx, s.conn, StageResolve); err != nil {
		return AttemptResolution{}, err
	}
	stored, err := s.loadStoredAttempt(ctx, s.conn, id, StageResolve)
	if err != nil {
		return AttemptResolution{}, err
	}
	if !bytes.Equal(stored.stateDigest, expectedToken[:]) {
		return AttemptResolution{}, classified(ErrConsent, StageResolve, ReasonStale)
	}
	view, err := validateSuppliedRepositoryView(input, s.binding, s.limits, stored.core.Kind == string(AttemptGenesis))
	if err != nil {
		return AttemptResolution{}, err
	}
	if err := s.validateAttemptPolicy(stored.core, view.input.SuppliedContext, StageResolve); err != nil {
		return AttemptResolution{}, err
	}
	outcome, evidence, err := s.deriveAttemptOutcome(stored, view)
	if err != nil {
		return AttemptResolution{}, err
	}
	if err := preserveTerminalOutcome(stored, outcome, evidence); err != nil {
		return AttemptResolution{}, err
	}
	if stored.lifecycle == AttemptRetiredAbandoned || stored.lifecycle == AttemptRetiredSuccess {
		return AttemptResolution{}, classified(ErrConsent, StageResolve, ReasonTransition)
	}
	if !bytes.Equal(stored.terminal, evidence) || outcome != stored.outcome {
		if err := s.preflightSidecars(); err != nil {
			return AttemptResolution{}, storageFailure(ctx, StageResolve, err)
		}
		var nextMutation uint64
		var nextStateDigest [32]byte
		var resolvedAttempt Attempt
		err = s.withTx(ctx, StageResolve, func(tx *sql.Tx) error {
			fresh, err := s.loadStoredAttempt(ctx, tx, id, StageResolve)
			if err != nil {
				return err
			}
			if !bytes.Equal(fresh.stateDigest, expectedToken[:]) {
				return classified(ErrConsent, StageResolve, ReasonStale)
			}
			if err := s.validateAttemptPolicy(fresh.core, view.input.SuppliedContext, StageResolve); err != nil {
				return err
			}
			freshOutcome, freshEvidence, err := s.deriveAttemptOutcome(fresh, view)
			if err != nil {
				return err
			}
			if err := preserveTerminalOutcome(fresh, freshOutcome, freshEvidence); err != nil {
				return err
			}
			kind := ""
			if freshOutcome != fresh.outcome {
				kind = "outcome-" + string(freshOutcome)
			}
			freshRole := "outcome"
			if freshOutcome == OutcomeLostFence && !terminalOutcome(fresh.outcome) {
				nextMutation, err = s.updateAttemptTxWithFirstConflict(ctx, tx, fresh, fresh.lifecycle, freshOutcome, fresh.blocked, freshRole, freshEvidence, nil, kind, nil, freshEvidence, &nextStateDigest, StageResolve)
			} else {
				nextMutation, err = s.updateAttemptTx(ctx, tx, fresh, fresh.lifecycle, freshOutcome, fresh.blocked, freshRole, freshEvidence, nil, kind, nil, &nextStateDigest, StageResolve)
			}
			if err != nil {
				return err
			}
			resolvedAttempt = projectAttempt(fresh.core, fresh.lifecycle, freshOutcome, fresh.blocked, nextMutation, AvailabilityUnchecked)
			resolvedAttempt.StateDigest = nextStateDigest
			return nil
		})
		if err != nil {
			return AttemptResolution{}, err
		}
		s.attemptMutationRevision = nextMutation
		attempt := resolvedAttempt
		return AttemptResolution{Attempt: attempt, Outcome: outcome, ViewDigest: view.digest, Evidence: bytes.Clone(evidence)}, nil
	}
	attempt := projectAttempt(stored.core, stored.lifecycle, stored.outcome, stored.blocked, stored.mutationRevision, AvailabilityUnchecked)
	copy(attempt.StateDigest[:], stored.stateDigest)
	return AttemptResolution{Attempt: attempt, Outcome: outcome, ViewDigest: view.digest, Evidence: bytes.Clone(evidence)}, nil
}

func (s *Store) deriveAttemptOutcome(stored storedAttempt, view validatedRepositoryView) (AttemptOutcome, []byte, error) {
	if stored.lifecycle != AttemptMayHaveSubmitted && stored.lifecycle != AttemptRetiredSuccess && stored.lifecycle != AttemptRetiredAbandoned {
		return OutcomeNotSubmitted, nil, nil
	}
	if view.empty {
		if stored.core.Kind != string(AttemptGenesis) {
			return "", nil, classified(ErrContinuity, StageResolve, ReasonMissingLineage)
		}
		evidence, err := s.compactAttemptEvidence(stored, view, OutcomeAbsentUnresolved)
		return OutcomeAbsentUnresolved, evidence, err
	}
	observed, occupied := view.byKey[stored.core.SnapshotKey]
	if !occupied {
		if stored.core.Kind != string(AttemptSuccessor) || !absenceViewPreservesPredecessor(stored, view) {
			return "", nil, classified(ErrContinuity, StageResolve, ReasonMissingLineage)
		}
		evidence, err := s.compactAttemptEvidence(stored, view, OutcomeAbsentUnresolved)
		return OutcomeAbsentUnresolved, evidence, err
	}
	if bytes.Equal(observed.ref.CID, stored.core.SnapshotCID) && bytes.Equal(observed.raw, stored.core.SnapshotRecord) {
		if view.head.PublicationSeq == observed.ref.Sequence && bytes.Equal(view.head.SnapshotCID, observed.ref.CID) {
			evidence, err := s.compactAttemptEvidence(stored, view, OutcomeCurrent)
			return OutcomeCurrent, evidence, err
		}
		if view.head.PublicationSeq > observed.ref.Sequence {
			evidence, err := s.compactAttemptEvidence(stored, view, OutcomeSuperseded)
			return OutcomeSuperseded, evidence, err
		}
		return "", nil, classified(ErrInvalid, StageResolve, ReasonRecordSet)
	}
	if view.head.PublicationSeq < observed.ref.Sequence {
		return "", nil, classified(ErrInvalid, StageResolve, ReasonRecordSet)
	}
	if stored.core.Kind == string(AttemptSuccessor) {
		floor, err := floorFromWire(*stored.core.CapturedFloor)
		if err != nil {
			return "", nil, classified(ErrSchema, StageResolve, ReasonCorrupt)
		}
		predecessor, ok := view.byCID[string(floor.RecordCID)]
		if !ok || !bytes.Equal(predecessor.raw, stored.core.PredecessorRecord) || observed.ref.Sequence != floor.Sequence+1 {
			return "", nil, classified(ErrContinuity, StageResolve, ReasonMissingLineage)
		}
	} else if observed.ref.Sequence != 0 {
		return "", nil, classified(ErrContinuity, StageResolve, ReasonMissingLineage)
	}
	evidence, err := s.compactAttemptEvidence(stored, view, OutcomeLostFence)
	return OutcomeLostFence, evidence, err
}

func absenceViewPreservesPredecessor(stored storedAttempt, view validatedRepositoryView) bool {
	if stored.core.CapturedFloor == nil {
		return false
	}
	floor, err := floorFromWire(*stored.core.CapturedFloor)
	if err != nil {
		return false
	}
	predecessor, ok := view.byCID[string(floor.RecordCID)]
	return ok && bytes.Equal(predecessor.raw, stored.core.PredecessorRecord) && view.head.PublicationSeq == floor.Sequence && bytes.Equal(view.head.SnapshotCID, floor.RecordCID)
}

func (s *Store) compactAttemptEvidence(stored storedAttempt, view validatedRepositoryView, outcome AttemptOutcome) ([]byte, error) {
	var attempted []byte
	var suffix []SnapshotBlock
	if record, ok := view.byKey[stored.core.SnapshotKey]; ok {
		attempted = bytes.Clone(record.raw)
		for _, block := range view.input.Snapshots {
			sequence, err := publication.ParseSequenceKey(block.Key)
			if err == nil && sequence >= record.ref.Sequence {
				suffix = append(suffix, SnapshotBlock{Key: block.Key, Raw: bytes.Clone(block.Raw)})
			}
		}
	}
	wire := attemptEvidenceWire{Version: 1, Role: "outcome", Scope: string(view.input.Scope), ViewDigest: bytes.Clone(view.digest[:]), Origin: bindingToWire(view.input.Origin), Context: contextToWire(view.input.SuppliedContext), Head: bytes.Clone(view.input.Head), AttemptedKey: stored.core.SnapshotKey, AttemptedRecord: attempted, PredecessorRecord: bytes.Clone(stored.core.PredecessorRecord), Suffix: suffix, Outcome: string(outcome)}
	encoded, err := encodeAttemptEvidence(wire)
	if err != nil || uint64(len(encoded)) > s.attemptLimits.EvidenceSlotBytes {
		return nil, classified(ErrLimit, StageResolve, ReasonCapacity)
	}
	return encoded, nil
}

func preserveTerminalOutcome(stored storedAttempt, next AttemptOutcome, evidence []byte) error {
	if !terminalOutcome(stored.outcome) {
		return nil
	}
	switch stored.outcome {
	case OutcomeCurrent:
		if next != OutcomeCurrent && next != OutcomeSuperseded {
			return classified(ErrContinuity, StageResolve, ReasonCorrupt)
		}
	case OutcomeSuperseded:
		if next != OutcomeSuperseded {
			return classified(ErrContinuity, StageResolve, ReasonCorrupt)
		}
	case OutcomeLostFence:
		if next != OutcomeLostFence {
			return classified(ErrContinuity, StageResolve, ReasonCorrupt)
		}
	}
	if !terminalEvidenceExtends(stored.terminal, evidence) {
		return classified(ErrContinuity, StageResolve, ReasonCorrupt)
	}
	return nil
}

func (s *Store) validateAttemptPolicy(core attemptCoreWire, context SuppliedContext, stage Stage) error {
	initial, err := contextFromWire(core.InitialContext)
	if err != nil {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	if !samePolicy(initial.Policy, context.Policy) {
		return classified(ErrContinuity, stage, ReasonContext)
	}
	return nil
}

func terminalOutcome(outcome AttemptOutcome) bool {
	return outcome == OutcomeCurrent || outcome == OutcomeSuperseded || outcome == OutcomeLostFence
}

func terminalEvidenceExtends(old, next []byte) bool {
	var previous, refreshed attemptEvidenceWire
	if strictJSON(old, &previous) != nil || strictJSON(next, &refreshed) != nil || previous.Role != "outcome" || refreshed.Role != "outcome" || previous.AttemptedKey != refreshed.AttemptedKey || !bytes.Equal(previous.AttemptedRecord, refreshed.AttemptedRecord) || !bytes.Equal(previous.PredecessorRecord, refreshed.PredecessorRecord) || len(previous.Suffix) == 0 || len(previous.Suffix) > len(refreshed.Suffix) {
		return false
	}
	for index, block := range previous.Suffix {
		if block.Key != refreshed.Suffix[index].Key || !bytes.Equal(block.Raw, refreshed.Suffix[index].Raw) {
			return false
		}
	}
	return true
}
