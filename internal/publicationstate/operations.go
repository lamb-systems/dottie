package publicationstate

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"errors"

	"github.com/lamb-systems/dottie/internal/publication"
)

type queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func queryInt64(ctx context.Context, q queryer, query string, args ...any) (int64, error) {
	var value any
	if err := q.QueryRowContext(ctx, query, args...).Scan(&value); err != nil {
		return 0, err
	}
	number, ok := rawInt64(value)
	if !ok {
		return 0, errStoredValue
	}
	return number, nil
}
func queryReadError(ctx context.Context, stage Stage, err error) error {
	if errors.Is(err, errStoredValue) {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	return storageFailure(ctx, stage, err)
}

type stateSnapshot struct {
	floor      *Floor
	revision   uint64
	generation uint64
	token      [32]byte
}

type resolvedTrace struct {
	refs    []RecordReference
	records []validatedRecord
	stop    string
	reason  Reason
}

type cacheObservationWire struct {
	Version           uint32        `json:"version"`
	ObservationDigest []byte        `json:"observationDigest"`
	SuppliedSetDigest []byte        `json:"suppliedSetDigest"`
	Context           contextWire   `json:"context"`
	Head              []byte        `json:"head"`
	Candidate         referenceWire `json:"candidate"`
}

func (s *Store) RecordObservation(ctx context.Context, observation Observation) ([32]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkContext(ctx, StageObserve); err != nil {
		return [32]byte{}, err
	}
	if err := s.requireReadback(StageObserve); err != nil {
		return [32]byte{}, err
	}
	validated, err := validateObservation(observation, s.binding, s.limits)
	if err != nil {
		return [32]byte{}, err
	}
	metadata, err := canonicalJSON(cacheObservationWire{Version: 1, ObservationDigest: bytes.Clone(validated.observationDigest[:]), SuppliedSetDigest: bytes.Clone(validated.setDigest[:]), Context: contextToWire(validated.context), Head: bytes.Clone(validated.head), Candidate: referenceToWire(validated.candidate.ref)})
	if err != nil {
		return [32]byte{}, classified(ErrInvalid, StageInput, ReasonRecordSet)
	}
	if err := s.preflightSidecars(); err != nil {
		return [32]byte{}, storageFailure(ctx, StageObserve, err)
	}
	err = s.withTx(ctx, StageObserve, func(tx *sql.Tx) error {
		metadataLength, err := queryInt64(ctx, tx, "SELECT length(metadata) FROM cache_observations WHERE observation_id=?", validated.observationID[:])
		if err == nil {
			if metadataLength < 0 || metadataLength > 32768 {
				return classified(ErrSchema, StageObserve, ReasonCorrupt)
			}
			var existingValue any
			if err := tx.QueryRowContext(ctx, "SELECT metadata FROM cache_observations WHERE observation_id=?", validated.observationID[:]).Scan(&existingValue); err != nil {
				return storageFailure(ctx, StageObserve, err)
			}
			existing, ok := rawBytes(existingValue)
			if !ok {
				return classified(ErrSchema, StageObserve, ReasonCorrupt)
			}
			if !bytes.Equal(existing, metadata) {
				return classified(ErrSchema, StageObserve, ReasonCorrupt)
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return storageFailure(ctx, StageObserve, err)
		}
		recordCount, err := queryInt64(ctx, tx, "SELECT COUNT(*) FROM cache_records")
		if err != nil {
			return queryReadError(ctx, StageObserve, err)
		}
		observationCount, err := queryInt64(ctx, tx, "SELECT COUNT(*) FROM cache_observations")
		if err != nil {
			return queryReadError(ctx, StageObserve, err)
		}
		cacheBytes, err := queryInt64(ctx, tx, "SELECT COALESCE(SUM(logical_bytes),0) FROM cache_records")
		if err != nil {
			return queryReadError(ctx, StageObserve, err)
		}
		observationBytes, err := queryInt64(ctx, tx, "SELECT COALESCE(SUM(logical_bytes),0) FROM cache_observations")
		if err != nil {
			return queryReadError(ctx, StageObserve, err)
		}
		cacheBytes += observationBytes
		newRecords := make([]validatedRecord, 0, len(validated.blocks))
		var newBytes uint64
		for _, record := range validated.blocks {
			var raw []byte
			var key string
			var sequence uint64
			rawLength, err := queryInt64(ctx, tx, "SELECT length(raw) FROM cache_records WHERE cid=?", record.ref.CID)
			if err == nil {
				if rawLength <= 0 || rawLength > publication.MaxRecordBytes {
					return classified(ErrSchema, StageObserve, ReasonCorrupt)
				}
				var keyValue, sequenceValue, rawValue any
				err = tx.QueryRowContext(ctx, "SELECT record_key,sequence,raw FROM cache_records WHERE cid=?", record.ref.CID).Scan(&keyValue, &sequenceValue, &rawValue)
				if err == nil {
					var valid bool
					key, valid = keyValue.(string)
					if !valid {
						return classified(ErrSchema, StageObserve, ReasonCorrupt)
					}
					seq, valid := rawInt64(sequenceValue)
					if !valid || seq < 0 {
						return classified(ErrSchema, StageObserve, ReasonCorrupt)
					}
					sequence = uint64(seq)
					raw, valid = rawBytes(rawValue)
					if !valid {
						return classified(ErrSchema, StageObserve, ReasonCorrupt)
					}
				}
			}
			if err == nil {
				if key != record.ref.Key || sequence != record.ref.Sequence || !bytes.Equal(raw, record.raw) {
					return classified(ErrSchema, StageObserve, ReasonCorrupt)
				}
				continue
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return storageFailure(ctx, StageObserve, err)
			}
			newRecords = append(newRecords, record)
			newBytes += recordLogicalBytes(record)
		}
		obsBytes := uint64(len(metadata) + 32 + 8)
		if uint64(recordCount)+uint64(len(newRecords)) > uint64(s.limits.CacheRecordCount) || uint64(observationCount)+1 > uint64(s.limits.CacheObservationCount) || uint64(cacheBytes)+newBytes+obsBytes > s.limits.CacheLogicalBytes {
			return classified(ErrLimit, StageObserve, ReasonCapacity)
		}
		for _, record := range newRecords {
			if _, err := tx.ExecContext(ctx, "INSERT INTO cache_records(cid,record_key,sequence,raw,logical_bytes) VALUES(?,?,?,?,?)", record.ref.CID, record.ref.Key, record.ref.Sequence, record.raw, recordLogicalBytes(record)); err != nil {
				return classified(ErrStorage, StageObserve, ReasonIO)
			}
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO cache_observations(observation_id,metadata,logical_bytes) VALUES(?,?,?)", validated.observationID[:], metadata, obsBytes); err != nil {
			return classified(ErrStorage, StageObserve, ReasonIO)
		}
		return nil
	})
	if err != nil {
		return [32]byte{}, err
	}
	return validated.observationID, nil
}

func (s *Store) Prepare(ctx context.Context, mode Mode, observation Observation, payload []byte) (Proposal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkContext(ctx, StagePrepare); err != nil {
		return Proposal{}, err
	}
	if err := s.requireReadback(StagePrepare); err != nil {
		return Proposal{}, err
	}
	if !validMode(mode) {
		return Proposal{}, classified(ErrInvalid, StageInput, ReasonMode)
	}
	validated, err := validateObservation(observation, s.binding, s.limits)
	if err != nil {
		return Proposal{}, err
	}
	if _, err := publication.DecodePayload(payload, blobReference(validated.candidate.raw)); err != nil {
		return Proposal{}, err
	}
	state, err := s.readState(ctx, s.conn, StagePrepare)
	if err != nil {
		return Proposal{}, err
	}
	trace, err := s.resolveTrace(ctx, s.conn, validated, state.floor, StagePrepare)
	if err != nil {
		return Proposal{}, err
	}
	return s.proposal(mode, validated, state, trace, StagePrepare)
}

func (s *Store) Accept(ctx context.Context, mode Mode, expectedStateToken [32]byte, observation Observation, payload []byte, confirmation [32]byte) (Floor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkContext(ctx, StageAccept); err != nil {
		return zeroFloor(), err
	}
	if err := s.requireReadback(StageAccept); err != nil {
		return zeroFloor(), err
	}
	if !validMode(mode) {
		return zeroFloor(), classified(ErrInvalid, StageInput, ReasonMode)
	}
	validated, err := validateObservation(observation, s.binding, s.limits)
	if err != nil {
		return zeroFloor(), err
	}
	if _, err := publication.DecodePayload(payload, blobReference(validated.candidate.raw)); err != nil {
		return zeroFloor(), err
	}
	if err := s.preflightSidecars(); err != nil {
		return zeroFloor(), storageFailure(ctx, StageAccept, err)
	}
	var accepted Floor
	var attemptMutationChanged bool
	err = s.withTx(ctx, StageAccept, func(tx *sql.Tx) error {
		floor, changed, txErr := s.acceptTx(ctx, tx, StageAccept, mode, expectedStateToken, validated, confirmation, nil)
		if txErr != nil {
			return txErr
		}
		accepted = floor
		attemptMutationChanged = changed
		return nil
	})
	if err != nil {
		return zeroFloor(), err
	}
	if attemptMutationChanged {
		s.attemptMutationRevision++
	}
	return cloneFloor(accepted), nil
}

func (s *Store) acceptFloorTx(ctx context.Context, tx *sql.Tx, mode Mode, state stateSnapshot, validated validatedObservation, trace resolvedTrace, stage Stage, reservationAttemptID []byte) (Floor, error) {
	if state.revision >= publication.MaxSequence || state.generation >= publication.MaxSequence && (mode == ModeFirstUse || mode == ModeReplaceFloor) {
		return zeroFloor(), classified(ErrLimit, stage, ReasonCapacity)
	}
	if mode == ModeReplaceFloor && state.generation >= publication.MaxSequence {
		return zeroFloor(), classified(ErrLimit, stage, ReasonCapacity)
	}
	next := buildFloor(s.databaseID, s.binding, validated, state, trace, mode)
	next.Revision = state.revision + 1
	if mode == ModeFirstUse {
		next.Generation = 1
	}
	if mode == ModeReplaceFloor {
		next.Generation = state.generation + 1
	}
	body, err := makeEventBody(mode, trace.reason, state.floor, next, trace.refs, trace.stop, validated.observationDigest, validated.setDigest)
	if err != nil {
		return zeroFloor(), classified(ErrInvalid, stage, ReasonRecordSet)
	}
	eventDigest := domainHash("systems.lamb.dottie.local-publication-event.v1", body)
	next.AcceptedEventDigest = eventDigest
	encodedNext, err := encodeFloor(next)
	if err != nil {
		return zeroFloor(), classified(ErrInvalid, stage, ReasonRecordSet)
	}
	var oldEncoded []byte
	if state.floor != nil {
		oldEncoded, err = encodeFloor(*state.floor)
		if err != nil {
			return zeroFloor(), classified(ErrSchema, stage, ReasonCorrupt)
		}
	}
	logicalEventBytes := eventLogicalBytes(body, eventDigest[:], oldEncoded, encodedNext, string(mode), string(trace.reason), trace.stop)
	historyEventBytes := uint64(len(body) + len(eventDigest) + 8)
	seenTrace := make(map[string]bool)
	for _, record := range trace.records {
		if !seenTrace[string(record.ref.CID)] {
			seenTrace[string(record.ref.CID)] = true
			historyEventBytes += recordLogicalBytes(record)
		}
	}
	if state.floor != nil {
		anchor, err := s.loadRecordByCID(ctx, tx, state.floor.RecordCID, state.floor.SnapshotKey, state.floor.Sequence, stage)
		if err != nil {
			return zeroFloor(), err
		}
		if !seenTrace[string(anchor.ref.CID)] {
			historyEventBytes += recordLogicalBytes(anchor)
		}
	}
	if historyEventBytes > s.limits.HistoryEvidenceBytes {
		return zeroFloor(), classified(ErrLimit, stage, ReasonCapacity)
	}
	validatedNext, validationErr := s.validateEventWire(ctx, tx, body, encodedNext, eventDigest[:], oldEncoded, string(mode), string(trace.reason), trace.stop, next.Revision, trace.records, logicalEventBytes, stage)
	if validationErr != nil {
		return zeroFloor(), validationErr
	}
	next = validatedNext
	encodedNext, err = encodeFloor(next)
	if err != nil {
		return zeroFloor(), classified(ErrInvalid, stage, ReasonRecordSet)
	}
	if err := s.checkAcceptedCapacityWithReservation(ctx, tx, trace.records, logicalEventBytes, reservationAttemptID, stage); err != nil {
		return zeroFloor(), err
	}
	for _, record := range trace.records {
		if err := insertAcceptedRecord(ctx, tx, record); err != nil {
			return zeroFloor(), err
		}
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO accepted_events(revision,mode,reason,stop,old_floor,new_floor,body,digest,logical_bytes) VALUES(?,?,?,?,?,?,?,?,?)", next.Revision, string(mode), string(trace.reason), trace.stop, nullable(oldEncoded), encodedNext, body, eventDigest[:], logicalEventBytes); err != nil {
		return zeroFloor(), classified(ErrStorage, stage, ReasonIO)
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO active_floor(singleton,floor) VALUES(1,?) ON CONFLICT(singleton) DO UPDATE SET floor=excluded.floor", encodedNext); err != nil {
		return zeroFloor(), classified(ErrStorage, stage, ReasonIO)
	}
	if _, err := tx.ExecContext(ctx, "UPDATE store_meta SET value=? WHERE key='revision'", uint64Bytes(next.Revision)); err != nil {
		return zeroFloor(), classified(ErrStorage, stage, ReasonIO)
	}
	if _, err := tx.ExecContext(ctx, "UPDATE store_meta SET value=? WHERE key='generation'", uint64Bytes(next.Generation)); err != nil {
		return zeroFloor(), classified(ErrStorage, stage, ReasonIO)
	}
	return cloneFloor(next), nil
}

func (s *Store) rejectActiveCandidate(ctx context.Context, q queryer, candidate validatedRecord, stage Stage) error {
	var idValue, coreValue any
	err := q.QueryRowContext(ctx, "SELECT publication_attempts.attempt_id,publication_attempts.core FROM active_publication_attempt JOIN publication_attempts USING(attempt_id) WHERE active_publication_attempt.singleton=1").Scan(&idValue, &coreValue)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return storageFailure(ctx, stage, err)
	}
	coreBytes, ok := rawBytes(coreValue)
	if !ok {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	core, err := decodeAttemptCore(coreBytes)
	if err != nil {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	if bytes.Equal(core.SnapshotCID, candidate.ref.CID) && bytes.Equal(core.SnapshotRecord, candidate.raw) {
		return classified(ErrConsent, stage, ReasonActiveAttempt)
	}
	return nil
}

func validMode(mode Mode) bool {
	return mode == ModeFirstUse || mode == ModeAdvance || mode == ModeReplaceFloor
}

func (s *Store) proposal(mode Mode, observation validatedObservation, state stateSnapshot, trace resolvedTrace, stage Stage) (Proposal, error) {
	proposal := Proposal{Mode: mode, Reason: trace.reason, StateToken: state.token, ObservationID: observation.observationID, ObservationDigest: observation.observationDigest, Trace: cloneReferences(trace.refs), Stop: trace.stop}
	switch mode {
	case ModeFirstUse:
		if state.floor != nil {
			return Proposal{}, classified(ErrConsent, stage, ReasonMode)
		}
		proposal.Warning = WarningFirstUse
	case ModeAdvance:
		if state.floor == nil {
			return Proposal{}, classified(ErrContinuity, stage, ReasonFirstUseRequired)
		}
		if trace.stop == "same" || trace.stop == "joined" {
			return proposal, nil
		}
		return Proposal{}, classified(ErrContinuity, stage, trace.reason)
	case ModeReplaceFloor:
		if state.floor == nil || trace.reason == "" {
			return Proposal{}, classified(ErrConsent, stage, ReasonMode)
		}
		proposal.Warning = WarningReplacement
	default:
		return Proposal{}, classified(ErrInvalid, StageInput, ReasonMode)
	}
	confirmation, err := makeConfirmation(s.databaseID, s.binding, mode, state.floor, state.token, observation.observationDigest, trace.refs, trace.stop, trace.reason, proposal.Warning)
	if err != nil {
		return Proposal{}, classified(ErrInvalid, StageInput, ReasonRecordSet)
	}
	proposal.Confirmation = confirmation
	return proposal, nil
}

func (s *Store) resolveTrace(ctx context.Context, source queryer, observation validatedObservation, floor *Floor, stage Stage) (resolvedTrace, error) {
	candidate := observation.candidate
	trace := resolvedTrace{refs: []RecordReference{cloneReference(candidate.ref)}, records: []validatedRecord{cloneValidatedRecord(candidate)}}
	if floor == nil {
		trace.stop = "first_use"
		return trace, nil
	}
	if candidate.ref.Sequence < floor.Sequence {
		trace.stop = "rollback"
		trace.reason = ReasonRollback
		return trace, nil
	}
	if candidate.ref.Sequence == floor.Sequence {
		held, err := s.loadRecordByCID(ctx, source, floor.RecordCID, floor.SnapshotKey, floor.Sequence, stage)
		if err != nil {
			return resolvedTrace{}, err
		}
		if bytes.Equal(candidate.ref.CID, floor.RecordCID) && bytes.Equal(candidate.raw, held.raw) {
			trace.stop = "same"
			return trace, nil
		}
		trace.stop = "fork"
		trace.reason = ReasonFork
		return trace, nil
	}
	current := candidate
	links := uint32(0)
	for {
		if links >= s.limits.MaxLineageLinks {
			trace.stop = "walk_limit"
			trace.reason = ReasonMissingLineage
			return trace, nil
		}
		links++
		currentRecord, err := publication.DecodeSnapshot(current.raw)
		if err != nil {
			return resolvedTrace{}, storedOrInputError(stage, err)
		}
		if current.ref.Sequence == floor.Sequence+1 {
			if !bytes.Equal(currentRecord.Parent, floor.RecordCID) {
				trace.stop = "fork"
				trace.reason = ReasonFork
				return trace, nil
			}
			old, err := s.loadRecordByCID(ctx, source, floor.RecordCID, floor.SnapshotKey, floor.Sequence, stage)
			if err != nil {
				return resolvedTrace{}, err
			}
			if err := publication.VerifySuccessor(old.raw, current.raw, current.ref.Key); err != nil {
				return resolvedTrace{}, classified(ErrSchema, stage, ReasonCorrupt)
			}
			trace.stop = "joined"
			return trace, nil
		}
		parent, err := s.lookupParent(ctx, source, observation, currentRecord.Parent, stage)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				trace.stop = "missing_parent"
				trace.reason = ReasonMissingLineage
				return trace, nil
			}
			return resolvedTrace{}, err
		}
		if err := publication.VerifySuccessor(parent.raw, current.raw, current.ref.Key); err != nil {
			return resolvedTrace{}, classified(ErrInvalid, StageInput, ReasonRecordSet)
		}
		trace.refs = append(trace.refs, cloneReference(parent.ref))
		trace.records = append(trace.records, cloneValidatedRecord(parent))
		current = parent
	}
}

func (s *Store) lookupParent(ctx context.Context, source queryer, observation validatedObservation, cid []byte, stage Stage) (validatedRecord, error) {
	if record, ok := observation.byCID[string(cid)]; ok {
		return cloneValidatedRecord(record), nil
	}
	return s.loadAnyRecordByCID(ctx, source, cid, stage)
}

func (s *Store) loadAnyRecordByCID(ctx context.Context, source queryer, cid []byte, stage Stage) (validatedRecord, error) {
	record, err := s.queryRecord(ctx, source, "accepted_records", cid, stage)
	if err == nil {
		return s.verifyStoredRecord(record, stage)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return validatedRecord{}, err
	}
	record, err = s.queryRecord(ctx, source, "cache_records", cid, stage)
	if err != nil {
		return validatedRecord{}, err
	}
	return s.verifyStoredRecord(record, stage)
}

type rawStoredRecord struct {
	key      string
	sequence uint64
	cid, raw []byte
}

func (s *Store) queryRecord(ctx context.Context, source queryer, table string, cid []byte, stage Stage) (rawStoredRecord, error) {
	if table != "accepted_records" && table != "cache_records" {
		return rawStoredRecord{}, classified(ErrSchema, stage, ReasonCorrupt)
	}
	var rawLength any
	err := source.QueryRowContext(ctx, "SELECT length(raw) FROM "+table+" WHERE cid=?", cid).Scan(&rawLength)
	if errors.Is(err, sql.ErrNoRows) {
		return rawStoredRecord{}, sql.ErrNoRows
	}
	if err != nil {
		return rawStoredRecord{}, storageFailure(ctx, stage, err)
	}
	length, ok := rawLength.(int64)
	if !ok || length <= 0 || length > publication.MaxRecordBytes {
		return rawStoredRecord{}, classified(ErrSchema, stage, ReasonCorrupt)
	}
	var keyValue, sequenceValue, cidValue, rawValue any
	err = source.QueryRowContext(ctx, "SELECT record_key,sequence,cid,raw FROM "+table+" WHERE cid=?", cid).Scan(&keyValue, &sequenceValue, &cidValue, &rawValue)
	if errors.Is(err, sql.ErrNoRows) {
		return rawStoredRecord{}, classified(ErrSchema, stage, ReasonCorrupt)
	}
	if err != nil {
		return rawStoredRecord{}, storageFailure(ctx, stage, err)
	}
	key, keyOK := keyValue.(string)
	sequence, sequenceOK := sequenceValue.(int64)
	storedCID, cidOK := cidValue.([]byte)
	raw, rawOK := rawValue.([]byte)
	if !keyOK || !sequenceOK || sequence < 0 || !cidOK || !rawOK {
		return rawStoredRecord{}, classified(ErrSchema, stage, ReasonCorrupt)
	}
	return rawStoredRecord{key: key, sequence: uint64(sequence), cid: bytes.Clone(storedCID), raw: bytes.Clone(raw)}, nil
}

func (s *Store) verifyStoredRecord(stored rawStoredRecord, stage Stage) (validatedRecord, error) {
	if len(stored.raw) == 0 || len(stored.raw) > publication.MaxRecordBytes || len(stored.cid) == 0 {
		return validatedRecord{}, classified(ErrSchema, stage, ReasonCorrupt)
	}
	record, err := publication.DecodeSnapshot(stored.raw)
	if err != nil || record.Vault != s.binding.Vault || record.PublicationSeq != stored.sequence {
		return validatedRecord{}, classified(ErrSchema, stage, ReasonCorrupt)
	}
	sequence, err := publication.ParseSequenceKey(stored.key)
	if err != nil || sequence != stored.sequence {
		return validatedRecord{}, classified(ErrSchema, stage, ReasonCorrupt)
	}
	computed, err := publication.RecordCID(stored.raw)
	if err != nil || !bytes.Equal(computed, stored.cid) {
		return validatedRecord{}, classified(ErrSchema, stage, ReasonCorrupt)
	}
	return validatedRecord{ref: RecordReference{Key: stored.key, CID: bytes.Clone(stored.cid), Sequence: stored.sequence}, raw: bytes.Clone(stored.raw)}, nil
}

func (s *Store) loadRecordByCID(ctx context.Context, source queryer, cid []byte, key string, sequence uint64, stage Stage) (validatedRecord, error) {
	record, err := s.queryRecord(ctx, source, "accepted_records", cid, stage)
	if errors.Is(err, sql.ErrNoRows) {
		return validatedRecord{}, classified(ErrSchema, stage, ReasonCorrupt)
	}
	if err != nil {
		var closed *Error
		if errors.As(err, &closed) {
			return validatedRecord{}, err
		}
		return validatedRecord{}, storageFailure(ctx, stage, err)
	}
	validated, err := s.verifyStoredRecord(record, stage)
	if err != nil || validated.ref.Key != key || validated.ref.Sequence != sequence || !bytes.Equal(validated.ref.CID, cid) {
		return validatedRecord{}, classified(ErrSchema, stage, ReasonCorrupt)
	}
	return validated, nil
}

func (s *Store) readState(ctx context.Context, source queryer, stage Stage) (stateSnapshot, error) {
	var state stateSnapshot
	revisionRaw, err := readMeta(ctx, source, "revision")
	if err != nil {
		return stateSnapshot{}, storedOrQueryError(ctx, stage, err)
	}
	if len(revisionRaw) != 8 {
		return stateSnapshot{}, classified(ErrSchema, stage, ReasonCorrupt)
	}
	generationRaw, err := readMeta(ctx, source, "generation")
	if err != nil {
		return stateSnapshot{}, storedOrQueryError(ctx, stage, err)
	}
	if len(generationRaw) != 8 {
		return stateSnapshot{}, classified(ErrSchema, stage, ReasonCorrupt)
	}
	state.revision = binary.BigEndian.Uint64(revisionRaw)
	state.generation = binary.BigEndian.Uint64(generationRaw)
	if state.revision > publication.MaxSequence || state.generation > publication.MaxSequence {
		return stateSnapshot{}, classified(ErrSchema, stage, ReasonCorrupt)
	}
	var floorRaw []byte
	var floorLengthValue any
	err = source.QueryRowContext(ctx, "SELECT length(floor) FROM active_floor WHERE singleton=1").Scan(&floorLengthValue)
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	} else if err != nil {
		return stateSnapshot{}, storageFailure(ctx, stage, err)
	} else {
		floorLength, ok := floorLengthValue.(int64)
		if !ok || floorLength <= 0 || floorLength > 65536 {
			return stateSnapshot{}, classified(ErrSchema, stage, ReasonCorrupt)
		}
		var floorValue any
		if err = source.QueryRowContext(ctx, "SELECT floor FROM active_floor WHERE singleton=1").Scan(&floorValue); err != nil {
			return stateSnapshot{}, storageFailure(ctx, stage, err)
		}
		var valid bool
		floorRaw, valid = floorValue.([]byte)
		if !valid {
			return stateSnapshot{}, classified(ErrSchema, stage, ReasonCorrupt)
		}
		floor, decodeErr := decodeFloor(floorRaw)
		if decodeErr != nil || validatePersistedFloor(floor, s.binding, s.databaseID, s.limits) != nil || floor.Revision != state.revision || floor.Generation != state.generation {
			return stateSnapshot{}, classified(ErrSchema, stage, ReasonCorrupt)
		}
		state.floor = &floor
	}
	if err := s.verifyAudit(ctx, source, state, stage); err != nil {
		return stateSnapshot{}, err
	}
	if s.schemaVersion >= 2 {
		mutationRevision, err := s.reconcileAttemptMutationRevision(ctx, source, stage)
		if err != nil {
			return stateSnapshot{}, err
		}
		if mutationRevision < s.attemptMutationRevision {
			return stateSnapshot{}, classified(ErrSchema, stage, ReasonCorrupt)
		}
		if err := s.checkAttemptGraph(ctx, source, stage); err != nil {
			return stateSnapshot{}, err
		}
	}
	if s.schemaVersion == 3 {
		if err := s.checkIncomingMaterialRefs(ctx, source, stage); err != nil {
			return stateSnapshot{}, err
		}
	}
	if s.schemaVersion >= 2 {
		state.token, err = s.expandedPositionToken(ctx, source, state, stage)
	} else {
		state.token, err = makeStateToken(s.databaseID, state.revision, state.generation, s.binding, s.limits, state.floor)
	}
	if err != nil {
		return stateSnapshot{}, classified(ErrSchema, stage, ReasonCorrupt)
	}
	return state, nil
}

func scanRawValues(rows *sql.Rows, count int) ([]any, error) {
	values := make([]any, count)
	dest := make([]any, count)
	for i := range values {
		dest[i] = &values[i]
	}
	if err := rows.Scan(dest...); err != nil {
		return nil, err
	}
	return values, nil
}
func rawInt64(value any) (int64, bool)  { number, ok := value.(int64); return number, ok }
func rawBytes(value any) ([]byte, bool) { data, ok := value.([]byte); return data, ok }
func rawNullableBytes(value any) ([]byte, bool) {
	if value == nil {
		return nil, true
	}
	return rawBytes(value)
}

func (s *Store) verifyAudit(ctx context.Context, source queryer, state stateSnapshot, stage Stage) error {
	var aggregates [3]any
	if err := source.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(SUM(logical_bytes),0),COALESCE(SUM(length(body)+COALESCE(length(old_floor),0)+length(new_floor)+length(digest)),0) FROM accepted_events").Scan(&aggregates[0], &aggregates[1], &aggregates[2]); err != nil {
		return storageFailure(ctx, stage, err)
	}
	eventCount, eventCountOK := rawInt64(aggregates[0])
	eventLogical, eventLogicalOK := rawInt64(aggregates[1])
	eventPayloadBytes, eventPayloadOK := rawInt64(aggregates[2])
	if !eventCountOK || !eventLogicalOK || !eventPayloadOK {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	if eventCount < 0 || eventLogical < 0 || eventPayloadBytes < 0 || uint64(eventCount) > uint64(s.limits.AcceptedEventCount) || uint64(eventLogical) > s.limits.AcceptedLogicalBytes || uint64(eventPayloadBytes) > s.limits.AcceptedLogicalBytes {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	var recordAggregates [3]any
	if err := source.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(SUM(length(raw)),0),COALESCE(SUM(logical_bytes),0) FROM accepted_records").Scan(&recordAggregates[0], &recordAggregates[1], &recordAggregates[2]); err != nil {
		return storageFailure(ctx, stage, err)
	}
	recordCount, recordCountOK := rawInt64(recordAggregates[0])
	recordRawBytes, recordRawOK := rawInt64(recordAggregates[1])
	recordLogical, recordLogicalOK := rawInt64(recordAggregates[2])
	if !recordCountOK || !recordRawOK || !recordLogicalOK {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	if recordCount < 0 || recordRawBytes < 0 || recordLogical < 0 || uint64(recordCount) > uint64(s.limits.AcceptedRecordCount) || uint64(recordRawBytes) > s.limits.AcceptedLogicalBytes || uint64(recordLogical) > s.limits.AcceptedLogicalBytes || uint64(eventLogical)+uint64(recordLogical) > s.limits.AcceptedLogicalBytes {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	rows, err := source.QueryContext(ctx, "SELECT revision,mode,reason,stop,old_floor,new_floor,body,digest,logical_bytes FROM accepted_events WHERE length(body)<=? AND length(new_floor)<=65536 AND (old_floor IS NULL OR length(old_floor)<=65536) ORDER BY revision", s.limits.HistoryEvidenceBytes)
	if err != nil {
		return storageFailure(ctx, stage, err)
	}
	defer rows.Close()
	var revision uint64
	var previous *Floor
	referencedRecords := make(map[string]bool)
	for rows.Next() {
		values, scanErr := scanRawValues(rows, 9)
		if scanErr != nil {
			return storageFailure(ctx, stage, scanErr)
		}
		revisionValue, revisionOK := rawInt64(values[0])
		mode, modeOK := values[1].(string)
		reason, reasonOK := values[2].(string)
		stop, stopOK := values[3].(string)
		oldRaw, oldOK := rawNullableBytes(values[4])
		newRaw, newOK := rawBytes(values[5])
		body, bodyOK := rawBytes(values[6])
		digest, digestOK := rawBytes(values[7])
		logical, logicalOK := rawInt64(values[8])
		if !revisionOK || revisionValue < 0 || !modeOK || !reasonOK || !stopOK || !oldOK || !newOK || !bodyOK || !digestOK || !logicalOK {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
		currentRevision := uint64(revisionValue)
		if currentRevision != revision+1 || logical < 0 || len(digest) != 32 {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
		var event eventBodyWire
		if strictJSON(body, &event) != nil || event.Version != 1 || event.Mode != mode || event.Reason != reason || event.Stop != stop || len(event.ObservationDigest) != 32 || len(event.SuppliedSetDigest) != 32 || event.Trace == nil || len(event.Trace) == 0 || len(event.Trace) > int(s.limits.MaxLineageLinks)+1 {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
		calculated := domainHash("systems.lamb.dottie.local-publication-event.v1", body)
		if !bytes.Equal(calculated[:], digest) {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
		newFloor, err := decodeFloor(newRaw)
		if err != nil || validatePersistedFloor(newFloor, s.binding, s.databaseID, s.limits) != nil || newFloor.Revision != currentRevision || newFloor.AcceptedEventDigest != calculated {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
		newCoreBytes, _ := canonicalJSON(floorCoreToWire(newFloor))
		eventCoreBytes, _ := canonicalJSON(event.NewFloor)
		if !bytes.Equal(newCoreBytes, eventCoreBytes) || !bytes.Equal(event.ObservationDigest, newFloor.ObservationDigest[:]) || uint64(logical) != eventLogicalBytes(body, digest, oldRaw, newRaw, mode, reason, stop) {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
		if previous == nil {
			if len(oldRaw) != 0 || event.OldFloor != nil || newFloor.Revision != 1 || newFloor.Generation != 1 || newFloor.Provenance != ProvenanceFirst {
				return classified(ErrSchema, stage, ReasonCorrupt)
			}
		} else {
			oldFloor, decodeErr := decodeFloor(oldRaw)
			if decodeErr != nil || event.OldFloor == nil || !bytes.Equal(oldRaw, mustCanonicalFloor(*previous)) {
				return classified(ErrSchema, stage, ReasonCorrupt)
			}
			oldWireBytes, _ := canonicalJSON(floorToWire(oldFloor))
			eventOldBytes, _ := canonicalJSON(event.OldFloor)
			if !bytes.Equal(oldWireBytes, eventOldBytes) || oldFloor.Revision != previous.Revision || newFloor.Generation < oldFloor.Generation || newFloor.Generation > oldFloor.Generation+1 {
				return classified(ErrSchema, stage, ReasonCorrupt)
			}
		}
		records := make([]validatedRecord, 0, len(event.Trace))
		for _, wire := range event.Trace {
			if len(wire.Key) != publication.SequenceKeyLength || len(wire.CID) == 0 || len(wire.CID) > publication.MaxCIDBytes {
				return classified(ErrSchema, stage, ReasonCorrupt)
			}
			sequence, keyErr := publication.ParseSequenceKey(wire.Key)
			if keyErr != nil || sequence != wire.Sequence {
				return classified(ErrSchema, stage, ReasonCorrupt)
			}
			ref := RecordReference{Key: wire.Key, CID: bytes.Clone(wire.CID), Sequence: wire.Sequence}
			record, err := s.loadRecordByCID(ctx, source, ref.CID, ref.Key, ref.Sequence, stage)
			if err != nil {
				return err
			}
			referencedRecords[string(ref.CID)] = true
			records = append(records, record)
		}
		if len(records) == 0 || !bytes.Equal(records[0].ref.CID, newFloor.RecordCID) || records[0].ref.Key != newFloor.SnapshotKey || records[0].ref.Sequence != newFloor.Sequence {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
		candidateRecord, decodeErr := publication.DecodeSnapshot(records[0].raw)
		if decodeErr != nil || candidateRecord.PublicationID != newFloor.PublicationID || !bytes.Equal(candidateRecord.Blob.CID, newFloor.BlobCID) || candidateRecord.Blob.Size != newFloor.BlobSize || publication.VerifyHeadBinding(newFloor.Head, records[0].raw, newFloor.SnapshotKey) != nil {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
		if previous == nil {
			if !bytes.Equal(newFloor.AnchorCID, newFloor.RecordCID) || newFloor.Provenance != ProvenanceFirst || mode != string(ModeFirstUse) || stop != "first_use" || reason != "" || len(records) != 1 {
				return classified(ErrSchema, stage, ReasonCorrupt)
			}
		} else if mode == string(ModeReplaceFloor) {
			if newFloor.Generation != previous.Generation+1 || newFloor.Provenance != ProvenanceReplace || !bytes.Equal(newFloor.AnchorCID, newFloor.RecordCID) || reason == "" || stop == "joined" || stop == "same" || stop == "first_use" {
				return classified(ErrSchema, stage, ReasonCorrupt)
			}
			if err := verifyDiscontinuousEvent(previous, records, Reason(reason), stop, s.limits); err != nil {
				return classified(ErrSchema, stage, ReasonCorrupt)
			}
		} else if mode == string(ModeAdvance) {
			if newFloor.Generation != previous.Generation || newFloor.Provenance != previous.Provenance || !bytes.Equal(newFloor.AnchorCID, previous.AnchorCID) || stop != "joined" || reason != "" {
				return classified(ErrSchema, stage, ReasonCorrupt)
			}
		} else {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
		for index := 0; index+1 < len(records); index++ {
			if err := publication.VerifySuccessor(records[index+1].raw, records[index].raw, records[index].ref.Key); err != nil {
				return classified(ErrSchema, stage, ReasonCorrupt)
			}
		}
		if _, err := s.validateEventWire(ctx, source, body, newRaw, digest, oldRaw, mode, reason, stop, currentRevision, records, uint64(logical), stage); err != nil {
			return err
		}
		if stop == "joined" {
			if previous == nil || len(records) == 0 {
				return classified(ErrSchema, stage, ReasonCorrupt)
			}
			oldRecord, err := s.loadRecordByCID(ctx, source, previous.RecordCID, previous.SnapshotKey, previous.Sequence, stage)
			if err != nil || publication.VerifySuccessor(oldRecord.raw, records[len(records)-1].raw, records[len(records)-1].ref.Key) != nil {
				return classified(ErrSchema, stage, ReasonCorrupt)
			}
		}
		previous = &newFloor
		revision = currentRevision
	}
	if err := rows.Err(); err != nil {
		return storageFailure(ctx, stage, err)
	}
	if err := rows.Close(); err != nil {
		return storageFailure(ctx, stage, err)
	}
	if revision != state.revision || (previous == nil) != (state.floor == nil) {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	if previous != nil && !bytes.Equal(mustCanonicalFloor(*previous), mustCanonicalFloor(*state.floor)) {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	if previous == nil && (state.revision != 0 || state.generation != 0) {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	if previous != nil && state.generation != previous.Generation {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	if err := s.verifyAcceptedRecords(ctx, source, referencedRecords, stage); err != nil {
		return err
	}
	return nil
}

func validatePersistedFloor(floor Floor, binding Binding, databaseID [32]byte, limits Limits) error {
	if validateBinding(floor.Binding) != nil || !sameBinding(floor.Binding, binding) || floor.DatabaseID != databaseID || floor.Revision == 0 || floor.Revision > publication.MaxSequence || floor.Generation == 0 || floor.Generation > publication.MaxSequence || len(floor.AnchorCID) == 0 || len(floor.RecordCID) == 0 || len(floor.RecordCID) > publication.MaxCIDBytes || len(floor.BlobCID) == 0 || len(floor.BlobCID) > publication.MaxCIDBytes || len(floor.Head) == 0 || len(floor.Head) > publication.MaxRecordBytes || len(floor.ObservationDigest) == 0 {
		return errors.New("floor")
	}
	if floor.Provenance != ProvenanceFirst && floor.Provenance != ProvenanceReplace {
		return errors.New("floor")
	}
	if sequence, err := publication.ParseSequenceKey(floor.SnapshotKey); err != nil || sequence != floor.Sequence {
		return errors.New("floor")
	}
	if validateContext(floor.SuppliedContext, binding, limits) != nil {
		return errors.New("floor")
	}
	return nil
}

func (s *Store) validateEventWire(ctx context.Context, source queryer, body, newRaw, digest, oldRaw []byte, mode, reason, stop string, revision uint64, records []validatedRecord, logical uint64, stage Stage) (Floor, error) {
	var event eventBodyWire
	if strictJSON(body, &event) != nil || event.Version != 1 || event.Mode != mode || event.Reason != reason || event.Stop != stop || len(event.ObservationDigest) != 32 || len(event.SuppliedSetDigest) != 32 || event.Trace == nil || len(event.Trace) == 0 || len(event.Trace) > int(s.limits.MaxLineageLinks)+1 {
		return Floor{}, classified(ErrSchema, stage, ReasonCorrupt)
	}
	calculated := domainHash("systems.lamb.dottie.local-publication-event.v1", body)
	if len(digest) != 32 || !bytes.Equal(calculated[:], digest) {
		return Floor{}, classified(ErrSchema, stage, ReasonCorrupt)
	}
	floor, err := decodeFloor(newRaw)
	if err != nil || validatePersistedFloor(floor, s.binding, s.databaseID, s.limits) != nil || floor.Revision != revision || floor.AcceptedEventDigest != calculated || !bytes.Equal(event.ObservationDigest, floor.ObservationDigest[:]) {
		return Floor{}, classified(ErrSchema, stage, ReasonCorrupt)
	}
	core, _ := canonicalJSON(floorCoreToWire(floor))
	encodedCore, _ := canonicalJSON(event.NewFloor)
	if !bytes.Equal(core, encodedCore) || logical != eventLogicalBytes(body, digest, oldRaw, newRaw, mode, reason, stop) {
		return Floor{}, classified(ErrSchema, stage, ReasonCorrupt)
	}
	var old *Floor
	var oldRecord *validatedRecord
	if len(oldRaw) == 0 {
		if event.OldFloor != nil {
			return Floor{}, classified(ErrSchema, stage, ReasonCorrupt)
		}
	} else {
		decoded, decodeErr := decodeFloor(oldRaw)
		if decodeErr != nil || event.OldFloor == nil {
			return Floor{}, classified(ErrSchema, stage, ReasonCorrupt)
		}
		oldBytes, _ := canonicalJSON(floorToWire(decoded))
		eventOld, _ := canonicalJSON(event.OldFloor)
		if !bytes.Equal(oldBytes, eventOld) {
			return Floor{}, classified(ErrSchema, stage, ReasonCorrupt)
		}
		old = &decoded
		anchor, anchorErr := s.loadRecordByCID(ctx, source, decoded.RecordCID, decoded.SnapshotKey, decoded.Sequence, stage)
		if anchorErr != nil {
			return Floor{}, anchorErr
		}
		oldRecord = &anchor
	}
	if len(event.Trace) != len(records) {
		return Floor{}, classified(ErrSchema, stage, ReasonCorrupt)
	}
	for index, wire := range event.Trace {
		ref := records[index].ref
		if wire.Key != ref.Key || wire.Sequence != ref.Sequence || !bytes.Equal(wire.CID, ref.CID) {
			return Floor{}, classified(ErrSchema, stage, ReasonCorrupt)
		}
	}
	if err := validateEventTransition(old, floor, Mode(mode), Reason(reason), stop, records, oldRecord, s.limits); err != nil {
		return Floor{}, classified(ErrSchema, stage, ReasonCorrupt)
	}
	return floor, nil
}

func validateEventTransition(old *Floor, next Floor, mode Mode, reason Reason, stop string, records []validatedRecord, oldRecord *validatedRecord, limits Limits) error {
	if len(records) == 0 {
		return errors.New("trace")
	}
	candidate, err := publication.DecodeSnapshot(records[0].raw)
	if err != nil || records[0].ref.Sequence != next.Sequence || records[0].ref.Key != next.SnapshotKey || !bytes.Equal(records[0].ref.CID, next.RecordCID) || candidate.PublicationID != next.PublicationID || !bytes.Equal(candidate.Blob.CID, next.BlobCID) || candidate.Blob.Size != next.BlobSize || publication.VerifyHeadBinding(next.Head, records[0].raw, next.SnapshotKey) != nil {
		return errors.New("candidate")
	}
	for index := 0; index+1 < len(records); index++ {
		if publication.VerifySuccessor(records[index+1].raw, records[index].raw, records[index].ref.Key) != nil {
			return errors.New("join")
		}
	}
	if old == nil {
		if mode != ModeFirstUse || reason != "" || stop != "first_use" || len(records) != 1 || next.Revision != 1 || next.Generation != 1 || next.Provenance != ProvenanceFirst || !bytes.Equal(next.AnchorCID, next.RecordCID) {
			return errors.New("first use")
		}
		return nil
	}
	if next.Revision != old.Revision+1 {
		return errors.New("revision")
	}
	switch mode {
	case ModeAdvance:
		if reason != "" || stop != "joined" || next.Generation != old.Generation || next.Provenance != old.Provenance || !bytes.Equal(next.AnchorCID, old.AnchorCID) || oldRecord == nil {
			return errors.New("advance")
		}
		return publication.VerifySuccessor(oldRecord.raw, records[len(records)-1].raw, records[len(records)-1].ref.Key)
	case ModeReplaceFloor:
		if next.Generation != old.Generation+1 || next.Provenance != ProvenanceReplace || !bytes.Equal(next.AnchorCID, next.RecordCID) || verifyDiscontinuousEvent(old, records, Reason(reason), stop, limits) != nil {
			return errors.New("replacement")
		}
		return nil
	default:
		return errors.New("mode")
	}
}

func verifyDiscontinuousEvent(old *Floor, records []validatedRecord, reason Reason, stop string, limits Limits) error {
	if len(records) == 0 {
		return errors.New("trace")
	}
	candidate, _ := publication.DecodeSnapshot(records[0].raw)
	switch reason {
	case ReasonRollback:
		if stop != "rollback" || candidate.PublicationSeq >= old.Sequence || len(records) != 1 {
			return errors.New("rollback")
		}
	case ReasonFork:
		if stop != "fork" {
			return errors.New("fork")
		}
		if candidate.PublicationSeq == old.Sequence {
			if len(records) != 1 || bytes.Equal(records[0].ref.CID, old.RecordCID) {
				return errors.New("fork")
			}
		} else if candidate.PublicationSeq == old.Sequence+1 {
			if len(records) != 1 || bytes.Equal(candidate.Parent, old.RecordCID) {
				return errors.New("fork")
			}
		} else if candidate.PublicationSeq > old.Sequence+1 {
			last := records[len(records)-1]
			lastRecord, err := publication.DecodeSnapshot(last.raw)
			if err != nil || last.ref.Sequence != old.Sequence+1 || bytes.Equal(lastRecord.Parent, old.RecordCID) {
				return errors.New("fork")
			}
		} else {
			return errors.New("fork")
		}
	case ReasonMissingLineage:
		if stop != "missing_parent" && stop != "walk_limit" {
			return errors.New("lineage")
		}
		if candidate.PublicationSeq <= old.Sequence+1 || (stop == "missing_parent" && records[len(records)-1].ref.Sequence <= old.Sequence+1) {
			return errors.New("lineage")
		}
		if stop == "walk_limit" && uint32(len(records)) != limits.MaxLineageLinks+1 {
			return errors.New("walk")
		}
	case "":
		return errors.New("reason")
	default:
		return errors.New("reason")
	}
	return nil
}

func (s *Store) verifyAcceptedRecords(ctx context.Context, source queryer, referenced map[string]bool, stage Stage) error {
	rows, err := source.QueryContext(ctx, "SELECT cid,record_key,sequence,raw,logical_bytes FROM accepted_records WHERE length(raw)<=?", publication.MaxRecordBytes)
	if err != nil {
		return storageFailure(ctx, stage, err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		values, scanErr := scanRawValues(rows, 5)
		if scanErr != nil {
			return storageFailure(ctx, stage, scanErr)
		}
		cid, cidOK := rawBytes(values[0])
		key, keyOK := values[1].(string)
		sequenceValue, sequenceOK := rawInt64(values[2])
		raw, rawOK := rawBytes(values[3])
		logical, logicalOK := rawInt64(values[4])
		if !cidOK || !keyOK || !sequenceOK || sequenceValue < 0 || !rawOK || !logicalOK {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
		sequence := uint64(sequenceValue)
		if len(raw) == 0 || len(raw) > publication.MaxRecordBytes {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
		stored := rawStoredRecord{key: key, sequence: sequence, cid: cid, raw: raw}
		record, err := s.verifyStoredRecord(stored, stage)
		if err != nil || uint64(logical) != recordLogicalBytes(record) || !referenced[string(cid)] {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return storageFailure(ctx, stage, err)
	}
	if err := rows.Close(); err != nil {
		return storageFailure(ctx, stage, err)
	}
	var actualValue any
	if err := source.QueryRowContext(ctx, "SELECT COUNT(*) FROM accepted_records").Scan(&actualValue); err != nil {
		return storageFailure(ctx, stage, err)
	}
	actualCount, ok := rawInt64(actualValue)
	if !ok || actualCount < 0 {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	if count != int(actualCount) {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	return nil
}

func (s *Store) checkAcceptedCapacity(ctx context.Context, tx *sql.Tx, records []validatedRecord, eventBytes uint64, stage Stage) error {
	return s.checkAcceptedCapacityWithReservation(ctx, tx, records, eventBytes, nil, stage)
}

func (s *Store) checkAcceptedCapacityWithReservation(ctx context.Context, tx queryer, records []validatedRecord, eventBytes uint64, excludedAttemptID []byte, stage Stage) error {
	currentCount, err := queryInt64(ctx, tx, "SELECT COUNT(*) FROM accepted_records")
	if err != nil {
		return queryReadError(ctx, stage, err)
	}
	eventCount, err := queryInt64(ctx, tx, "SELECT COUNT(*) FROM accepted_events")
	if err != nil {
		return queryReadError(ctx, stage, err)
	}
	currentBytes, err := queryInt64(ctx, tx, "SELECT COALESCE(SUM(logical_bytes),0) FROM accepted_records")
	if err != nil {
		return queryReadError(ctx, stage, err)
	}
	eventBytesCurrent, err := queryInt64(ctx, tx, "SELECT COALESCE(SUM(logical_bytes),0) FROM accepted_events")
	if err != nil {
		return queryReadError(ctx, stage, err)
	}
	currentBytes += eventBytesCurrent
	if currentCount < 0 || eventCount < 0 || currentBytes < 0 {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	newRecords := make([]validatedRecord, 0, len(records))
	var newBytes uint64
	seen := map[string]bool{}
	for _, record := range records {
		if seen[string(record.ref.CID)] {
			continue
		}
		seen[string(record.ref.CID)] = true
		var raw []byte
		var key string
		var seq uint64
		rawLength, err := queryInt64(ctx, tx, "SELECT length(raw) FROM accepted_records WHERE cid=?", record.ref.CID)
		if err == nil && (rawLength <= 0 || rawLength > publication.MaxRecordBytes) {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
		if err == nil {
			var keyValue, sequenceValue, rawValue any
			err = tx.QueryRowContext(ctx, "SELECT record_key,sequence,raw FROM accepted_records WHERE cid=?", record.ref.CID).Scan(&keyValue, &sequenceValue, &rawValue)
			if err == nil {
				var valid bool
				key, valid = keyValue.(string)
				if !valid {
					return classified(ErrSchema, stage, ReasonCorrupt)
				}
				number, valid := rawInt64(sequenceValue)
				if !valid || number < 0 {
					return classified(ErrSchema, stage, ReasonCorrupt)
				}
				seq = uint64(number)
				raw, valid = rawBytes(rawValue)
				if !valid {
					return classified(ErrSchema, stage, ReasonCorrupt)
				}
			}
		}
		if err == nil {
			if key != record.ref.Key || seq != record.ref.Sequence || !bytes.Equal(raw, record.raw) {
				return classified(ErrSchema, stage, ReasonCorrupt)
			}
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return storageFailure(ctx, stage, err)
		}
		newRecords = append(newRecords, record)
		newBytes += recordLogicalBytes(record)
	}
	var reservedBytes, reservedRecords, reservedEvents uint64
	rows, err := tx.QueryContext(ctx, "SELECT attempt_id,accepted_bytes,accepted_records,accepted_events FROM attempt_reservations")
	if err != nil {
		return storageFailure(ctx, stage, err)
	}
	for rows.Next() {
		var idValue, bytesValue, recordsValue, eventsValue any
		if err := rows.Scan(&idValue, &bytesValue, &recordsValue, &eventsValue); err != nil {
			_ = rows.Close()
			return storageFailure(ctx, stage, err)
		}
		id, idOK := rawBytes(idValue)
		byteCount, byteOK := rawInt64(bytesValue)
		recordCount, recordOK := rawInt64(recordsValue)
		eventCount, eventOK := rawInt64(eventsValue)
		if !idOK || len(id) != 16 || !byteOK || !recordOK || !eventOK || byteCount < 0 || recordCount < 0 || eventCount < 0 {
			_ = rows.Close()
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
		if len(excludedAttemptID) == 16 && bytes.Equal(id, excludedAttemptID) {
			continue
		}
		reservedBytes += uint64(byteCount)
		reservedRecords += uint64(recordCount)
		reservedEvents += uint64(eventCount)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return storageFailure(ctx, stage, err)
	}
	if err := rows.Close(); err != nil {
		return storageFailure(ctx, stage, err)
	}
	if uint64(currentCount)+uint64(len(newRecords))+reservedRecords > uint64(s.limits.AcceptedRecordCount) || uint64(eventCount)+1+reservedEvents > uint64(s.limits.AcceptedEventCount) || uint64(currentBytes)+newBytes+eventBytes+reservedBytes > s.limits.AcceptedLogicalBytes {
		return classified(ErrLimit, stage, ReasonCapacity)
	}
	return nil
}

func insertAcceptedRecord(ctx context.Context, tx *sql.Tx, record validatedRecord) error {
	var raw []byte
	var key string
	var seq uint64
	rawLength, err := queryInt64(ctx, tx, "SELECT length(raw) FROM accepted_records WHERE cid=?", record.ref.CID)
	if err == nil && (rawLength <= 0 || rawLength > publication.MaxRecordBytes) {
		return classified(ErrSchema, StageAccept, ReasonCorrupt)
	}
	if err == nil {
		var keyValue, sequenceValue, rawValue any
		err = tx.QueryRowContext(ctx, "SELECT record_key,sequence,raw FROM accepted_records WHERE cid=?", record.ref.CID).Scan(&keyValue, &sequenceValue, &rawValue)
		if err == nil {
			var valid bool
			key, valid = keyValue.(string)
			if !valid {
				return classified(ErrSchema, StageAccept, ReasonCorrupt)
			}
			number, valid := rawInt64(sequenceValue)
			if !valid || number < 0 {
				return classified(ErrSchema, StageAccept, ReasonCorrupt)
			}
			seq = uint64(number)
			raw, valid = rawBytes(rawValue)
			if !valid {
				return classified(ErrSchema, StageAccept, ReasonCorrupt)
			}
		}
	}
	if err == nil {
		if key != record.ref.Key || seq != record.ref.Sequence || !bytes.Equal(raw, record.raw) {
			return classified(ErrSchema, StageAccept, ReasonCorrupt)
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return storageFailure(ctx, StageAccept, err)
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO accepted_records(cid,record_key,sequence,raw,logical_bytes) VALUES(?,?,?,?,?)", record.ref.CID, record.ref.Key, record.ref.Sequence, record.raw, recordLogicalBytes(record)); err != nil {
		return classified(ErrStorage, StageAccept, ReasonIO)
	}
	return nil
}

func recordLogicalBytes(record validatedRecord) uint64 {
	return uint64(len(record.raw) + len(record.ref.CID) + len(record.ref.Key) + 8)
}

func eventLogicalBytes(body, digest, oldFloor, newFloor []byte, mode, reason, stop string) uint64 {
	return uint64(len(body) + len(digest) + len(oldFloor) + len(newFloor) + len(mode) + len(reason) + len(stop) + 8)
}

func buildFloor(dbid [32]byte, binding Binding, observation validatedObservation, state stateSnapshot, trace resolvedTrace, mode Mode) Floor {
	candidate := observation.candidate
	record, _ := publication.DecodeSnapshot(candidate.raw)
	var provenance Provenance
	var anchor []byte
	var generation uint64
	if mode == ModeFirstUse {
		provenance = ProvenanceFirst
		anchor = bytes.Clone(candidate.ref.CID)
		generation = 1
	} else if mode == ModeReplaceFloor {
		provenance = ProvenanceReplace
		anchor = bytes.Clone(candidate.ref.CID)
		generation = state.generation + 1
	} else {
		provenance = state.floor.Provenance
		anchor = bytes.Clone(state.floor.AnchorCID)
		generation = state.generation
	}
	return Floor{DatabaseID: dbid, Revision: state.revision + 1, Generation: generation, Provenance: provenance, AnchorCID: anchor, Binding: binding, SuppliedContext: cloneContext(observation.context), Head: bytes.Clone(observation.head), SnapshotKey: candidate.ref.Key, Sequence: candidate.ref.Sequence, PublicationID: record.PublicationID, RecordCID: bytes.Clone(candidate.ref.CID), BlobCID: bytes.Clone(record.Blob.CID), BlobSize: record.Blob.Size, ObservationDigest: observation.observationDigest}
}

func blobReference(raw []byte) publication.BlobReference {
	record, _ := publication.DecodeSnapshot(raw)
	return publication.BlobReference{CID: bytes.Clone(record.Blob.CID), Size: record.Blob.Size}
}

func cloneFloor(floor Floor) Floor {
	out := floor
	out.AnchorCID = bytes.Clone(floor.AnchorCID)
	out.Binding = floor.Binding
	out.SuppliedContext = cloneContext(floor.SuppliedContext)
	out.Head = bytes.Clone(floor.Head)
	out.RecordCID = bytes.Clone(floor.RecordCID)
	out.BlobCID = bytes.Clone(floor.BlobCID)
	return out
}
func cloneReference(ref RecordReference) RecordReference {
	return RecordReference{Key: ref.Key, CID: bytes.Clone(ref.CID), Sequence: ref.Sequence}
}
func cloneReferences(refs []RecordReference) []RecordReference {
	out := make([]RecordReference, 0, len(refs))
	for _, ref := range refs {
		out = append(out, cloneReference(ref))
	}
	return out
}
func cloneValidatedRecord(record validatedRecord) validatedRecord {
	return validatedRecord{ref: cloneReference(record.ref), raw: bytes.Clone(record.raw)}
}
func nullable(value []byte) any {
	if value == nil {
		return nil
	}
	return value
}
func mustCanonicalFloor(floor Floor) []byte { encoded, _ := encodeFloor(floor); return encoded }
func storedOrInputError(stage Stage, err error) error {
	if err != nil {
		return classified(ErrInvalid, StageInput, ReasonRecordSet)
	}
	return classified(ErrSchema, stage, ReasonCorrupt)
}
func (s *Store) preflightSidecars() error {
	for _, name := range []string{"publication.db", "publication.db.lock", "publication.db-wal", "publication.db-shm"} {
		if err := preflightFile(s.directory + "/" + name); err != nil {
			return err
		}
	}
	return nil
}
