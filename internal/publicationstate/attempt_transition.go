package publicationstate

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"math"
)

func (s *Store) updateAttemptTx(ctx context.Context, tx *sql.Tx, current storedAttempt, lifecycle AttemptLifecycle, outcome AttemptOutcome, blocked string, evidenceRole string, evidence []byte, retirement []byte, eventKind string, eventEvidence []byte, stateDigestResult *[32]byte, stage Stage) (uint64, error) {
	return s.updateAttemptTxWithFirstConflict(ctx, tx, current, lifecycle, outcome, blocked, evidenceRole, evidence, retirement, eventKind, eventEvidence, nil, stateDigestResult, stage)
}

func (s *Store) updateAttemptTxWithFirstConflict(ctx context.Context, tx *sql.Tx, current storedAttempt, lifecycle AttemptLifecycle, outcome AttemptOutcome, blocked string, evidenceRole string, evidence []byte, retirement []byte, eventKind string, eventEvidence, firstConflictProof []byte, stateDigestResult *[32]byte, stage Stage) (uint64, error) {
	mutation, err := s.reconcileAttemptMutationRevision(ctx, tx, stage)
	if err != nil {
		return 0, err
	}
	if mutation >= math.MaxInt64 {
		return 0, classified(ErrLimit, stage, ReasonCapacity)
	}
	nextMutation := mutation + 1
	terminal := bytes.Clone(current.terminal)
	if evidence != nil {
		terminal = bytes.Clone(evidence)
	}
	nextRetirement := bytes.Clone(current.retirement)
	if retirement != nil {
		nextRetirement = bytes.Clone(retirement)
	}
	digest, err := makeAttemptStateDigest(current.coreBytes, lifecycle, outcome, blocked, nextMutation, terminal, nextRetirement)
	if err != nil {
		return 0, classified(ErrSchema, stage, ReasonCorrupt)
	}
	if stateDigestResult != nil {
		*stateDigestResult = digest
	}
	var eventBody, eventDigest []byte
	var logicalIncrease int64
	if eventKind != "" {
		var ordinalValue any
		var previous []byte
		err := tx.QueryRowContext(ctx, "SELECT ordinal,digest FROM attempt_events WHERE attempt_id=? ORDER BY ordinal DESC LIMIT 1", current.core.AttemptID).Scan(&ordinalValue, &previous)
		ordinal := uint32(1)
		if err == nil {
			last, ok := rawInt64(ordinalValue)
			if !ok || last < 1 || uint64(last) >= uint64(s.attemptLimits.LifecycleEvents) || len(previous) != 32 {
				return 0, classified(ErrLimit, stage, ReasonCapacity)
			}
			ordinal = uint32(last + 1)
		} else if !errors.Is(err, sql.ErrNoRows) {
			return 0, storageFailure(ctx, stage, err)
		}
		if firstConflictProof != nil {
			var proof attemptEvidenceWire
			if eventKind != "outcome-lost-fence" || outcome != OutcomeLostFence || lifecycle != AttemptMayHaveSubmitted || evidenceRole != "outcome" || !bytes.Equal(evidence, firstConflictProof) || strictJSON(firstConflictProof, &proof) != nil || s.validateAttemptEvidenceWire(current, "outcome", proof) != nil {
				return 0, classified(ErrSchema, stage, ReasonCorrupt)
			}
			record, err := makeFirstConflictRecord(current, firstConflictProof, ordinal, nextMutation, digest, blocked)
			if err != nil || uint64(len(record.Body)) > s.attemptLimits.EvidenceSlotBytes {
				return 0, classified(ErrLimit, stage, ReasonCapacity)
			}
			var existsValue any
			if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM attempt_evidence WHERE attempt_id=? AND role='first-conflict')", current.core.AttemptID).Scan(&existsValue); err != nil {
				return 0, storageFailure(ctx, stage, err)
			}
			exists, ok := rawInt64(existsValue)
			if !ok || exists != 0 {
				return 0, classified(ErrSchema, stage, ReasonCorrupt)
			}
			var evidenceTotalValue any
			if err := tx.QueryRowContext(ctx, "SELECT COALESCE(SUM(length(body)+length(digest)),0) FROM attempt_evidence").Scan(&evidenceTotalValue); err != nil {
				return 0, storageFailure(ctx, stage, err)
			}
			evidenceTotal, ok := rawInt64(evidenceTotalValue)
			if !ok || evidenceTotal < 0 {
				return 0, classified(ErrSchema, stage, ReasonCorrupt)
			}
			newEvidenceTotal, fits := checkedAttemptAdd(uint64(evidenceTotal), uint64(len(record.Body)+len(record.Digest)))
			if !fits || newEvidenceTotal > s.attemptLimits.EvidenceBytes {
				return 0, classified(ErrLimit, stage, ReasonCapacity)
			}
			if _, err := tx.ExecContext(ctx, "INSERT INTO attempt_evidence(attempt_id,role,body,digest) VALUES(?, 'first-conflict', ?, ?)", current.core.AttemptID, record.Body, record.Digest); err != nil {
				return 0, classified(ErrStorage, stage, ReasonIO)
			}
			logicalIncrease += int64(len(record.Body) + len(record.Digest))
			eventEvidence = bytes.Clone(record.ID[:])
		} else if eventKind == "outcome-lost-fence" {
			return 0, classified(ErrSchema, stage, ReasonCorrupt)
		}
		var stateID [16]byte
		copy(stateID[:], current.core.AttemptID)
		eventBody, eventDigest, err = makeAttemptEvent(stateID, ordinal, eventKind, previous, eventEvidence, digest)
		if err != nil {
			return 0, classified(ErrSchema, stage, ReasonCorrupt)
		}
		if uint64(len(eventBody)+len(eventDigest)) > s.attemptLimits.EventBytes {
			return 0, classified(ErrLimit, stage, ReasonCapacity)
		}
		logicalIncrease += int64(len(eventBody) + len(eventDigest))
	}
	if evidenceRole != "" && evidence != nil {
		if uint64(len(evidence)) > s.attemptLimits.EvidenceSlotBytes {
			return 0, classified(ErrLimit, stage, ReasonCapacity)
		}
		var previousLengthValue any
		previousLength := int64(0)
		err := tx.QueryRowContext(ctx, "SELECT length(body)+length(digest) FROM attempt_evidence WHERE attempt_id=? AND role=?", current.core.AttemptID, evidenceRole).Scan(&previousLengthValue)
		if err == nil {
			var ok bool
			previousLength, ok = rawInt64(previousLengthValue)
			if !ok || previousLength < 0 {
				return 0, classified(ErrSchema, stage, ReasonCorrupt)
			}
		} else if !errors.Is(err, sql.ErrNoRows) {
			return 0, storageFailure(ctx, stage, err)
		}
		var evidenceTotalValue any
		if err := tx.QueryRowContext(ctx, "SELECT COALESCE(SUM(length(body)+length(digest)),0) FROM attempt_evidence").Scan(&evidenceTotalValue); err != nil {
			return 0, storageFailure(ctx, stage, err)
		}
		evidenceTotal, ok := rawInt64(evidenceTotalValue)
		if !ok || evidenceTotal < previousLength || uint64(evidenceTotal-previousLength)+uint64(len(evidence))+32 > s.attemptLimits.EvidenceBytes {
			return 0, classified(ErrLimit, stage, ReasonCapacity)
		}
		evidenceDigest := domainHash("systems.lamb.dottie.publication-attempt-evidence.v1", evidence)
		if _, err := tx.ExecContext(ctx, "INSERT INTO attempt_evidence(attempt_id,role,body,digest) VALUES(?,?,?,?) ON CONFLICT(attempt_id,role) DO UPDATE SET body=excluded.body,digest=excluded.digest", current.core.AttemptID, evidenceRole, evidence, evidenceDigest[:]); err != nil {
			return 0, classified(ErrStorage, stage, ReasonIO)
		}
		logicalIncrease += int64(len(evidence)+len(evidenceDigest)) - previousLength
	}
	if eventKind != "" {
		var ordinalValue any
		if err := tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(ordinal),0)+1 FROM attempt_events WHERE attempt_id=?", current.core.AttemptID).Scan(&ordinalValue); err != nil {
			return 0, storageFailure(ctx, stage, err)
		}
		ordinal, ok := rawInt64(ordinalValue)
		if !ok || ordinal <= 0 {
			return 0, classified(ErrSchema, stage, ReasonCorrupt)
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO attempt_events(attempt_id,ordinal,kind,body,digest) VALUES(?,?,?,?,?)", current.core.AttemptID, ordinal, eventKind, eventBody, eventDigest); err != nil {
			return 0, classified(ErrStorage, stage, ReasonIO)
		}
	}
	var usedValue, currentLogicalValue any
	if err := tx.QueryRowContext(ctx, "SELECT COALESCE(SUM(logical_bytes),0) FROM publication_attempts").Scan(&usedValue); err != nil {
		return 0, storageFailure(ctx, stage, err)
	}
	if err := tx.QueryRowContext(ctx, "SELECT logical_bytes FROM publication_attempts WHERE attempt_id=?", current.core.AttemptID).Scan(&currentLogicalValue); err != nil {
		return 0, storageFailure(ctx, stage, err)
	}
	used, usedOK := rawInt64(usedValue)
	currentLogical, logicalOK := rawInt64(currentLogicalValue)
	if !usedOK || !logicalOK || used < 0 || currentLogical < 0 || used < currentLogical || logicalIncrease < -currentLogical || used+logicalIncrease < 0 || uint64(used+logicalIncrease) > s.attemptLimits.MetadataBytes {
		return 0, classified(ErrLimit, stage, ReasonCapacity)
	}
	if _, err := tx.ExecContext(ctx, "UPDATE publication_attempts SET logical_bytes=logical_bytes+? WHERE attempt_id=?", logicalIncrease, current.core.AttemptID); err != nil {
		return 0, classified(ErrStorage, stage, ReasonIO)
	}
	if _, err := tx.ExecContext(ctx, "UPDATE publication_attempts SET lifecycle=?,outcome=?,blocked=?,state_digest=?,mutation_revision=?,terminal_evidence=?,retirement_evidence=? WHERE attempt_id=?", string(lifecycle), string(outcome), blocked, digest[:], int64(nextMutation), nullable(terminal), nullable(nextRetirement), current.core.AttemptID); err != nil {
		return 0, classified(ErrStorage, stage, ReasonIO)
	}
	if _, err := tx.ExecContext(ctx, "UPDATE store_meta SET value=? WHERE key='attempt_mutation_revision'", uint64Bytes(nextMutation)); err != nil {
		return 0, classified(ErrStorage, stage, ReasonIO)
	}
	return nextMutation, nil
}

func (s *Store) blockActiveAttemptTx(ctx context.Context, tx *sql.Tx, stage Stage) (bool, error) {
	var idValue any
	err := tx.QueryRowContext(ctx, "SELECT attempt_id FROM active_publication_attempt WHERE singleton=1").Scan(&idValue)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, storageFailure(ctx, stage, err)
	}
	id, ok := rawBytes(idValue)
	if !ok || len(id) != 16 {
		return false, classified(ErrSchema, stage, ReasonCorrupt)
	}
	var attemptID [16]byte
	copy(attemptID[:], id)
	current, err := s.loadStoredAttempt(ctx, tx, attemptID, stage)
	if err != nil {
		return false, err
	}
	eventKind := "blocked-floor-replaced"
	if current.blocked == "blocked-floor-replaced" {
		eventKind = ""
	}
	if _, err := s.updateAttemptTx(ctx, tx, current, current.lifecycle, current.outcome, "blocked-floor-replaced", "", nil, nil, eventKind, nil, nil, stage); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE attempt_reservations SET accepted_bytes=0,accepted_records=0,accepted_events=0,retained_points=0 WHERE attempt_id=?", id[:]); err != nil {
		return false, classified(ErrStorage, stage, ReasonIO)
	}
	return true, nil
}
