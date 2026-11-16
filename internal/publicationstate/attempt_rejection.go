package publicationstate

import (
	"bytes"
	"context"
	"database/sql"
)

func (s *Store) RejectAttempt(ctx context.Context, id [16]byte, expectedToken [32]byte) (Attempt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkContext(ctx, StageReject); err != nil {
		return Attempt{}, err
	}
	if err := s.requireReadback(StageReject); err != nil {
		return Attempt{}, err
	}
	if _, err := s.readState(ctx, s.conn, StageReject); err != nil {
		return Attempt{}, err
	}
	stored, err := s.loadStoredAttempt(ctx, s.conn, id, StageReject)
	if err != nil {
		return Attempt{}, err
	}
	if !bytes.Equal(stored.stateDigest, expectedToken[:]) {
		return Attempt{}, classified(ErrConsent, StageReject, ReasonStale)
	}
	if err := rejectableAttempt(stored, StageReject); err != nil {
		return Attempt{}, err
	}
	if err := s.preflightSidecars(); err != nil {
		return Attempt{}, storageFailure(ctx, StageReject, err)
	}
	var nextMutation uint64
	var rejectedAttempt Attempt
	err = s.withTx(ctx, StageReject, func(tx *sql.Tx) error {
		fresh, err := s.loadStoredAttempt(ctx, tx, id, StageReject)
		if err != nil {
			return err
		}
		if !bytes.Equal(fresh.stateDigest, expectedToken[:]) {
			return classified(ErrConsent, StageReject, ReasonStale)
		}
		if err := rejectableAttempt(fresh, StageReject); err != nil {
			return err
		}
		outcome, retirement, err := s.rejectionEvidence(fresh)
		if err != nil {
			return err
		}
		if _, err := s.updateAttemptTx(ctx, tx, fresh, AttemptMayHaveSubmitted, OutcomeRejected, "", "outcome", outcome, nil, "outcome-provider-rejected", nil, nil, StageReject); err != nil {
			return err
		}
		fresh.outcome = OutcomeRejected
		fresh.terminal = bytes.Clone(outcome)
		var newStateDigest [32]byte
		nextMutation, err = s.updateAttemptTx(ctx, tx, fresh, AttemptRetiredAbandoned, OutcomeRejected, "", "retirement", retirement, retirement, "retired-abandoned", nil, &newStateDigest, StageReject)
		if err != nil {
			return err
		}
		rejectedAttempt = projectAttempt(fresh.core, AttemptRetiredAbandoned, OutcomeRejected, "", nextMutation, AvailabilityUnchecked)
		rejectedAttempt.StateDigest = newStateDigest
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
				return classified(ErrStorage, StageReject, ReasonIO)
			}
		}
		return nil
	})
	if err != nil {
		return Attempt{}, err
	}
	s.attemptMutationRevision = nextMutation
	return rejectedAttempt, nil
}

func rejectableAttempt(stored storedAttempt, stage Stage) error {
	if stored.lifecycle != AttemptMayHaveSubmitted || stored.blocked != "" {
		return classified(ErrConsent, stage, ReasonTransition)
	}
	if stored.outcome != OutcomeUnresolved && stored.outcome != OutcomeAbsentUnresolved {
		return classified(ErrContinuity, stage, ReasonTransition)
	}
	return nil
}

func (s *Store) rejectionEvidence(stored storedAttempt) ([]byte, []byte, error) {
	outcome, err := encodeAttemptEvidence(attemptEvidenceWire{
		Version: 1, Role: "outcome", AttemptedKey: stored.core.SnapshotKey,
		PredecessorRecord: bytes.Clone(stored.core.PredecessorRecord), Outcome: string(OutcomeRejected),
	})
	if err != nil || uint64(len(outcome)) > s.attemptLimits.EvidenceSlotBytes {
		return nil, nil, classified(ErrLimit, StageReject, ReasonCapacity)
	}
	retirement, err := encodeAttemptEvidence(attemptEvidenceWire{
		Version: 1, Role: "retirement", AttemptedKey: stored.core.SnapshotKey,
		AttemptedRecord: bytes.Clone(stored.core.SnapshotRecord), Outcome: string(OutcomeRejected),
	})
	if err != nil || uint64(len(retirement)) > s.attemptLimits.EvidenceSlotBytes {
		return nil, nil, classified(ErrLimit, StageReject, ReasonCapacity)
	}
	return outcome, retirement, nil
}
