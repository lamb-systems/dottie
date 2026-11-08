package publicationstate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"io"
	"math"

	"github.com/lamb-systems/dottie/internal/publication"
	"golang.org/x/sys/unix"
)

type storedAttempt struct {
	core             attemptCoreWire
	coreBytes        []byte
	lifecycle        AttemptLifecycle
	outcome          AttemptOutcome
	blocked          string
	stateDigest      []byte
	mutationRevision uint64
	createdOrder     uint64
	logicalBytes     uint64
	terminal         []byte
	retirement       []byte
}

func (s *Store) PrepareAttempt(ctx context.Context, candidate CandidateInput, view SuppliedRepositoryView, review LocalReviewContext) (AttemptProposal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkContext(ctx, StageAttempt); err != nil {
		return AttemptProposal{}, err
	}
	if err := s.requireReadback(StageAttempt); err != nil {
		return AttemptProposal{}, err
	}
	if err := s.checkAttemptLifecycleMinimum(StageAttempt); err != nil {
		return AttemptProposal{}, err
	}
	state, err := s.readState(ctx, s.conn, StageAttempt)
	if err != nil {
		return AttemptProposal{}, err
	}
	activeID, activeDigest, active, err := s.currentActiveAttempt(ctx, s.conn, StageAttempt)
	if err != nil {
		return AttemptProposal{}, err
	}
	if active {
		return AttemptProposal{}, classified(ErrConsent, StageAttempt, ReasonActiveAttempt)
	}
	validated, err := s.validateAttemptInput(ctx, candidate, view, review, state, StageAttempt)
	if err != nil {
		return AttemptProposal{}, err
	}
	if err := s.checkFinalizationFeasibility(ctx, validated, state, StageAttempt); err != nil {
		return AttemptProposal{}, err
	}
	if err := s.checkAttemptAdmissionFeasibility(validated, StageAttempt); err != nil {
		return AttemptProposal{}, err
	}
	if err := s.checkAttemptAdmissionCapacity(ctx, s.conn); err != nil {
		return AttemptProposal{}, err
	}
	if err := s.checkPayloadCapacity(ctx, payloadBasename(validated.payload), uint64(len(validated.payload)), false); err != nil {
		return AttemptProposal{}, classified(ErrLimit, StageAttempt, ReasonCapacity)
	}
	if err := s.checkUnusedAttemptID(ctx, s.conn, validated.id, StageAttempt); err != nil {
		return AttemptProposal{}, err
	}
	token, err := makeAttemptToken(s.databaseID, state, s.attemptMutationRevision, activeID, activeDigest, s.limits, s.attemptLimits)
	if err != nil {
		return AttemptProposal{}, classified(ErrSchema, StageAttempt, ReasonCorrupt)
	}
	digest, err := candidateDigest(validated, state, review, s.databaseID)
	if err != nil {
		return AttemptProposal{}, classified(ErrInvalid, StageAttempt, ReasonRecordSet)
	}
	confirmation, err := makeCandidateConfirmation(s.databaseID, token, validated.id, digest, validated.view.digest, review)
	if err != nil {
		return AttemptProposal{}, classified(ErrInvalid, StageAttempt, ReasonRecordSet)
	}
	_, coreBytes, err := s.makeAttemptCore(validated, state, review, confirmation)
	if err != nil {
		return AttemptProposal{}, classified(ErrInvalid, StageAttempt, ReasonRecordSet)
	}
	if uint64(len(coreBytes)) > s.attemptLimits.CoreBytes {
		return AttemptProposal{}, classified(ErrLimit, StageAttempt, ReasonCapacity)
	}
	nextMutation := s.attemptMutationRevision + 1
	if nextMutation > math.MaxInt64 {
		return AttemptProposal{}, classified(ErrLimit, StageAttempt, ReasonCapacity)
	}
	if err := s.checkAttemptCreatedEvent(coreBytes, validated.id, nextMutation, StageAttempt); err != nil {
		return AttemptProposal{}, err
	}
	return AttemptProposal{AttemptID: validated.id, Kind: validated.kind, StateToken: token, CandidateDigest: digest, Confirmation: confirmation, CapturedFloor: cloneFloorPointer(state.floor), CapturedGeneration: state.generation, CandidateRecordCID: bytes.Clone(validated.snapshotCID), CandidateBlobCID: bytes.Clone(validated.blobCID), CandidateBlobSize: validated.snapshot.Blob.Size}, nil
}

func (s *Store) CreateAttempt(ctx context.Context, expectedToken [32]byte, candidate CandidateInput, view SuppliedRepositoryView, review LocalReviewContext, confirmation [32]byte) (Attempt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkContext(ctx, StageAttempt); err != nil {
		return Attempt{}, err
	}
	if err := s.requireReadback(StageAttempt); err != nil {
		return Attempt{}, err
	}
	if err := s.checkAttemptLifecycleMinimum(StageAttempt); err != nil {
		return Attempt{}, err
	}
	state, err := s.readState(ctx, s.conn, StageAttempt)
	if err != nil {
		return Attempt{}, err
	}
	activeID, activeDigest, active, err := s.currentActiveAttempt(ctx, s.conn, StageAttempt)
	if err != nil {
		return Attempt{}, err
	}
	if active {
		return Attempt{}, classified(ErrConsent, StageAttempt, ReasonActiveAttempt)
	}
	validated, err := s.validateAttemptInput(ctx, candidate, view, review, state, StageAttempt)
	if err != nil {
		return Attempt{}, err
	}
	if err := s.checkFinalizationFeasibility(ctx, validated, state, StageAttempt); err != nil {
		return Attempt{}, err
	}
	if err := s.checkAttemptAdmissionFeasibility(validated, StageAttempt); err != nil {
		return Attempt{}, err
	}
	if err := s.checkAttemptAdmissionCapacity(ctx, s.conn); err != nil {
		return Attempt{}, err
	}
	if err := s.checkUnusedAttemptID(ctx, s.conn, validated.id, StageAttempt); err != nil {
		return Attempt{}, err
	}
	token, err := makeAttemptToken(s.databaseID, state, s.attemptMutationRevision, activeID, activeDigest, s.limits, s.attemptLimits)
	if err != nil {
		return Attempt{}, classified(ErrSchema, StageAttempt, ReasonCorrupt)
	}
	digest, err := candidateDigest(validated, state, review, s.databaseID)
	if err != nil {
		return Attempt{}, classified(ErrInvalid, StageAttempt, ReasonRecordSet)
	}
	wantConfirmation, err := makeCandidateConfirmation(s.databaseID, token, validated.id, digest, validated.view.digest, review)
	if err != nil {
		return Attempt{}, classified(ErrInvalid, StageAttempt, ReasonRecordSet)
	}
	core, coreBytes, err := s.makeAttemptCore(validated, state, review, wantConfirmation)
	if err != nil {
		return Attempt{}, classified(ErrInvalid, StageAttempt, ReasonRecordSet)
	}
	if uint64(len(coreBytes)) > s.attemptLimits.CoreBytes {
		return Attempt{}, classified(ErrLimit, StageAttempt, ReasonCapacity)
	}
	nextMutation := s.attemptMutationRevision + 1
	if nextMutation > math.MaxInt64 {
		return Attempt{}, classified(ErrLimit, StageAttempt, ReasonCapacity)
	}
	if err := s.checkAttemptCreatedEvent(coreBytes, validated.id, nextMutation, StageAttempt); err != nil {
		return Attempt{}, err
	}
	if !bytes.Equal(expectedToken[:], token[:]) {
		return Attempt{}, classified(ErrConsent, StageAttempt, ReasonStale)
	}
	if !bytes.Equal(confirmation[:], wantConfirmation[:]) {
		return Attempt{}, classified(ErrConsent, StageAttempt, ReasonConfirmation)
	}
	if err := s.checkPayloadCapacity(ctx, payloadBasename(validated.payload), uint64(len(validated.payload)), true); err != nil {
		return Attempt{}, classified(ErrLimit, StageAttempt, ReasonCapacity)
	}
	basename, _, err := s.persistCandidatePayload(ctx, validated)
	if err != nil {
		if ctx.Err() != nil {
			return Attempt{}, canceled(StageCustody, ctx.Err())
		}
		return Attempt{}, classifyCandidateRead(err, StageCustody)
	}
	if err := s.preflightSidecars(); err != nil {
		return Attempt{}, storageFailure(ctx, StageAttempt, err)
	}
	var result Attempt
	err = s.withTx(ctx, StageAttempt, func(tx *sql.Tx) error {
		fresh, err := s.readState(ctx, tx, StageAttempt)
		if err != nil {
			return err
		}
		id, stateDigest, hasActive, err := s.currentActiveAttempt(ctx, tx, StageAttempt)
		if err != nil {
			return err
		}
		freshToken, err := makeAttemptToken(s.databaseID, fresh, s.attemptMutationRevision, id, stateDigest, s.limits, s.attemptLimits)
		if err != nil || hasActive || !bytes.Equal(expectedToken[:], freshToken[:]) {
			return classified(ErrConsent, StageAttempt, ReasonStale)
		}
		if err := s.checkAttemptAdmissionCapacity(ctx, tx); err != nil {
			return err
		}
		if err := s.checkUnusedAttemptID(ctx, tx, validated.id, StageAttempt); err != nil {
			return err
		}
		if err := s.checkAttemptAdmissionFeasibility(validated, StageAttempt); err != nil {
			return err
		}
		if err := s.checkAttemptCreatedEvent(coreBytes, validated.id, nextMutation, StageAttempt); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO payload_objects(blob_cid,size,basename,logical_bytes) VALUES(?,?,?,?) ON CONFLICT(blob_cid) DO NOTHING", validated.blobCID, int64(validated.snapshot.Blob.Size), basename, int64(validated.snapshot.Blob.Size)); err != nil {
			return classified(ErrStorage, StageAttempt, ReasonIO)
		}
		var existingName string
		var existingSize any
		if err := tx.QueryRowContext(ctx, "SELECT basename,size FROM payload_objects WHERE blob_cid=?", validated.blobCID).Scan(&existingName, &existingSize); err != nil {
			return storageFailure(ctx, StageAttempt, err)
		}
		size, ok := rawInt64(existingSize)
		if !ok || size <= 0 || uint64(size) != validated.snapshot.Blob.Size || existingName != basename {
			return classified(ErrSchema, StageAttempt, ReasonCorrupt)
		}
		attemptDigest, err := makeAttemptStateDigest(coreBytes, AttemptPrepared, OutcomeNotSubmitted, "", nextMutation, nil, nil)
		if err != nil {
			return classified(ErrInvalid, StageAttempt, ReasonRecordSet)
		}
		createdOrder := nextMutation
		logicalBytes := uint64(len(coreBytes))
		eventBody, eventDigest, err := makeAttemptEvent(validated.id, 1, "created", nil, nil, attemptDigest)
		if err != nil {
			return classified(ErrInvalid, StageAttempt, ReasonRecordSet)
		}
		logicalBytes += uint64(len(eventBody) + len(eventDigest))
		if _, err := tx.ExecContext(ctx, "INSERT INTO publication_attempts(attempt_id,core,lifecycle,outcome,blocked,state_digest,mutation_revision,created_order,logical_bytes,terminal_evidence,retirement_evidence) VALUES(?,?,?,?,?,?,?,?,?,?,?)", validated.id[:], coreBytes, string(AttemptPrepared), string(OutcomeNotSubmitted), "", attemptDigest[:], int64(nextMutation), int64(createdOrder), int64(logicalBytes), nil, nil); err != nil {
			return classified(ErrStorage, StageAttempt, ReasonIO)
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO attempt_payload_refs(attempt_id,blob_cid) VALUES(?,?)", validated.id[:], validated.blobCID); err != nil {
			return classified(ErrStorage, StageAttempt, ReasonIO)
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO active_publication_attempt(singleton,attempt_id) VALUES(1,?)", validated.id[:]); err != nil {
			return classified(ErrStorage, StageAttempt, ReasonIO)
		}
		if validated.kind == AttemptGenesis {
			if _, err := tx.ExecContext(ctx, "INSERT INTO pending_genesis(singleton,attempt_id,vault) VALUES(1,?,?)", validated.id[:], s.binding.Vault[:]); err != nil {
				return classified(ErrStorage, StageAttempt, ReasonIO)
			}
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO attempt_events(attempt_id,ordinal,kind,body,digest) VALUES(?,1,'created',?,?)", validated.id[:], eventBody, eventDigest); err != nil {
			return classified(ErrStorage, StageAttempt, ReasonIO)
		}
		reservationBytes := s.attemptReservationSize()
		if reservationBytes > math.MaxInt64 || logicalBytes > math.MaxInt64 {
			return classified(ErrLimit, StageAttempt, ReasonCapacity)
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO attempt_reservations(attempt_id,metadata_bytes,accepted_bytes,accepted_records,accepted_events,retained_points) VALUES(?,?,?,?,?,?)", validated.id[:], int64(reservationBytes), int64(512<<10), 2, 1, 1); err != nil {
			return classified(ErrStorage, StageAttempt, ReasonIO)
		}
		if _, err := tx.ExecContext(ctx, "UPDATE store_meta SET value=? WHERE key='attempt_mutation_revision'", uint64Bytes(nextMutation)); err != nil {
			return classified(ErrStorage, StageAttempt, ReasonIO)
		}
		result = projectAttempt(core, AttemptPrepared, OutcomeNotSubmitted, "", nextMutation, AvailabilityAvailable)
		result.StateDigest = attemptDigest
		return nil
	})
	if err != nil {
		return Attempt{}, err
	}
	s.attemptMutationRevision = nextMutation
	return result, nil
}

func (s *Store) checkAttemptLifecycleMinimum(stage Stage) error {
	if s.attemptLimits.LifecycleEvents < 8 {
		return classified(ErrLimit, stage, ReasonCapacity)
	}
	return nil
}

func (s *Store) checkAttemptCreatedEvent(core []byte, id [16]byte, mutationRevision uint64, stage Stage) error {
	if err := s.checkAttemptLifecycleMinimum(stage); err != nil {
		return err
	}
	digest, err := makeAttemptStateDigest(core, AttemptPrepared, OutcomeNotSubmitted, "", mutationRevision, nil, nil)
	if err != nil {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	body, eventDigest, err := makeAttemptEvent(id, 1, "created", nil, nil, digest)
	if err != nil {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	if uint64(len(body)+len(eventDigest)) > s.attemptLimits.EventBytes {
		return classified(ErrLimit, stage, ReasonCapacity)
	}
	return nil
}

func candidateDigest(candidate validatedCandidate, state stateSnapshot, review LocalReviewContext, databaseID [32]byte) ([32]byte, error) {
	hash := sha256.New()
	hash.Write([]byte("systems.lamb.dottie.publication-candidate.v1\x00"))
	var length [8]byte
	writePart := func(part []byte) {
		binary.BigEndian.PutUint64(length[:], uint64(len(part)))
		hash.Write(length[:])
		hash.Write(part)
	}
	var counters [16]byte
	binary.BigEndian.PutUint64(counters[:8], state.revision)
	binary.BigEndian.PutUint64(counters[8:], state.generation)
	writePart(databaseID[:])
	writePart(counters[:])
	if state.floor == nil {
		writePart(nil)
	} else {
		encoded, err := encodeFloor(*state.floor)
		if err != nil {
			return [32]byte{}, err
		}
		writePart(encoded)
	}
	writePart([]byte(candidate.key))
	writePart(candidate.snapshotRaw)
	writePart(candidate.headRaw)
	writePart(candidate.payload)
	writePart(candidate.view.digest[:])
	encodedReview, err := canonicalJSON(reviewToWire(review))
	if err != nil {
		return [32]byte{}, err
	}
	writePart(encodedReview)
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}

func (s *Store) makeAttemptCore(candidate validatedCandidate, state stateSnapshot, review LocalReviewContext, confirmation [32]byte) (attemptCoreWire, []byte, error) {
	var floor *floorWire
	var predecessorRaw, predecessorCID []byte
	var predecessorKey string
	if state.floor != nil {
		wire := floorToWire(*state.floor)
		floor = &wire
		if candidate.predecessor != nil {
			predecessorRaw = bytes.Clone(candidate.predecessor.raw)
			predecessorCID = bytes.Clone(candidate.predecessor.ref.CID)
			predecessorKey = candidate.predecessor.ref.Key
		}
	}
	core := attemptCoreWire{Version: 1, AttemptID: bytes.Clone(candidate.id[:]), DatabaseID: bytes.Clone(s.databaseID[:]), Binding: bindingToWire(s.binding), Kind: string(candidate.kind), CapturedFloor: floor, CapturedRevision: state.revision, CapturedGeneration: state.generation, PredecessorKey: predecessorKey, PredecessorRecord: predecessorRaw, PredecessorCID: predecessorCID, SnapshotKey: candidate.key, SnapshotRecord: bytes.Clone(candidate.snapshotRaw), SnapshotCID: bytes.Clone(candidate.snapshotCID), HeadRecord: bytes.Clone(candidate.headRaw), HeadCID: bytes.Clone(candidate.headCID), BlobCID: bytes.Clone(candidate.blobCID), BlobSize: candidate.snapshot.Blob.Size, InitialContext: contextToWire(candidate.view.input.SuppliedContext), InitialViewDigest: bytes.Clone(candidate.view.digest[:]), Review: reviewToWire(review), CandidateConfirmation: bytes.Clone(confirmation[:]), ReservedCompletionBytes: 512 << 10}
	encoded, err := encodeAttemptCore(core)
	return core, encoded, err
}

func makeAttemptEvent(id [16]byte, ordinal uint32, kind string, previousDigest, evidence []byte, stateDigest [32]byte) ([]byte, []byte, error) {
	wire := attemptEventWire{Version: 1, Ordinal: ordinal, Kind: kind, PreviousDigest: bytes.Clone(previousDigest), Evidence: bytes.Clone(evidence), StateDigest: bytes.Clone(stateDigest[:])}
	body, err := encodeAttemptEvent(wire)
	if err != nil {
		return nil, nil, err
	}
	digest := domainHash("systems.lamb.dottie.publication-attempt-event.v1", body)
	return body, bytes.Clone(digest[:]), nil
}

func (s *Store) checkUnusedAttemptID(ctx context.Context, q queryer, id [16]byte, stage Stage) error {
	var count any
	if err := q.QueryRowContext(ctx, "SELECT COUNT(*) FROM publication_attempts WHERE attempt_id=?", id[:]).Scan(&count); err != nil {
		return storageFailure(ctx, stage, err)
	}
	value, ok := rawInt64(count)
	if !ok || value < 0 {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	if value != 0 {
		return classified(ErrConsent, stage, ReasonStale)
	}
	return nil
}

func (s *Store) checkAttemptCompletionCapacity(ctx context.Context, q queryer, records []validatedRecord, eventLogicalBytes uint64, stage Stage) error {
	if ^uint64(0)-eventLogicalBytes < 512<<10 {
		return classified(ErrLimit, stage, ReasonCapacity)
	}
	if err := s.checkAcceptedCapacityWithReservation(ctx, q, records, eventLogicalBytes+(512<<10), nil, stage); err != nil {
		return err
	}
	currentCount, err := queryInt64(ctx, q, "SELECT COUNT(*) FROM accepted_records")
	if err != nil {
		return queryReadError(ctx, stage, err)
	}
	reservedCount, err := queryInt64(ctx, q, "SELECT COALESCE(SUM(accepted_records),0) FROM attempt_reservations")
	if err != nil {
		return queryReadError(ctx, stage, err)
	}
	newRecords := map[string]bool{}
	for _, record := range records {
		var exists any
		if err := q.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM accepted_records WHERE cid=?)", record.ref.CID).Scan(&exists); err != nil {
			return storageFailure(ctx, stage, err)
		}
		value, ok := rawInt64(exists)
		if !ok || value < 0 || value > 1 {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
		if value == 0 {
			newRecords[string(record.ref.CID)] = true
		}
	}
	if currentCount < 0 || reservedCount < 0 || uint64(currentCount)+uint64(len(newRecords))+uint64(reservedCount)+2 > uint64(s.limits.AcceptedRecordCount) {
		return classified(ErrLimit, stage, ReasonCapacity)
	}
	return nil
}

func (s *Store) checkAttemptAdmissionCapacity(ctx context.Context, q queryer) error {
	var countValue, bytesValue any
	if err := q.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(SUM(logical_bytes),0) FROM publication_attempts").Scan(&countValue, &bytesValue); err != nil {
		return storageFailure(ctx, StageAttempt, err)
	}
	count, countOK := rawInt64(countValue)
	used, bytesOK := rawInt64(bytesValue)
	if !countOK || !bytesOK || count < 0 || used < 0 || uint64(count) >= uint64(s.attemptLimits.HistoricalAttempts) || uint64(used) >= s.attemptLimits.MetadataBytes {
		return classified(ErrLimit, StageAttempt, ReasonCapacity)
	}
	var reservedValue any
	if err := q.QueryRowContext(ctx, "SELECT COALESCE(SUM(metadata_bytes),0) FROM attempt_reservations").Scan(&reservedValue); err != nil {
		return storageFailure(ctx, StageAttempt, err)
	}
	reserved, ok := rawInt64(reservedValue)
	if !ok || reserved < 0 {
		return classified(ErrSchema, StageAttempt, ReasonCorrupt)
	}
	metadataUsed, valid := checkedAttemptAdd(uint64(used), uint64(reserved))
	if valid {
		metadataUsed, valid = checkedAttemptAdd(metadataUsed, s.attemptReservationSize())
	}
	if !valid || metadataUsed > s.attemptLimits.MetadataBytes {
		return classified(ErrLimit, StageAttempt, ReasonCapacity)
	}
	var evidenceValue any
	if err := q.QueryRowContext(ctx, "SELECT COALESCE(SUM(length(body)+length(digest)),0) FROM attempt_evidence").Scan(&evidenceValue); err != nil {
		return storageFailure(ctx, StageAttempt, err)
	}
	evidenceUsed, ok := rawInt64(evidenceValue)
	if !ok || evidenceUsed < 0 {
		return classified(ErrSchema, StageAttempt, ReasonCorrupt)
	}
	evidenceReserved := 3 * (s.attemptLimits.EvidenceSlotBytes + 32)
	evidenceTotal, valid := checkedAttemptAdd(uint64(evidenceUsed), evidenceReserved)
	if !valid || evidenceTotal > s.attemptLimits.EvidenceBytes {
		return classified(ErrLimit, StageAttempt, ReasonCapacity)
	}
	var retainedValue any
	if err := q.QueryRowContext(ctx, "SELECT COUNT(*) FROM retained_publications").Scan(&retainedValue); err != nil {
		return storageFailure(ctx, StageAttempt, err)
	}
	retained, ok := rawInt64(retainedValue)
	if !ok || retained < 0 || uint64(retained) >= uint64(s.attemptLimits.RetainedPublications) {
		return classified(ErrLimit, StageAttempt, ReasonCapacity)
	}
	return nil
}

func (s *Store) currentActiveAttempt(ctx context.Context, q queryer, stage Stage) ([]byte, []byte, bool, error) {
	var idLengthValue, digestLengthValue any
	err := q.QueryRowContext(ctx, "SELECT length(publication_attempts.attempt_id),length(publication_attempts.state_digest) FROM active_publication_attempt JOIN publication_attempts USING(attempt_id) WHERE active_publication_attempt.singleton=1").Scan(&idLengthValue, &digestLengthValue)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, false, nil
	}
	if err != nil {
		return nil, nil, false, storageFailure(ctx, stage, err)
	}
	idLength, idLengthOK := rawInt64(idLengthValue)
	digestLength, digestLengthOK := rawInt64(digestLengthValue)
	if !idLengthOK || idLength != 16 || !digestLengthOK || digestLength != 32 {
		return nil, nil, false, classified(ErrSchema, stage, ReasonCorrupt)
	}
	var idValue, digestValue any
	if err := q.QueryRowContext(ctx, "SELECT publication_attempts.attempt_id,publication_attempts.state_digest FROM active_publication_attempt JOIN publication_attempts USING(attempt_id) WHERE active_publication_attempt.singleton=1").Scan(&idValue, &digestValue); err != nil {
		return nil, nil, false, storageFailure(ctx, stage, err)
	}
	id, idOK := rawBytes(idValue)
	digest, digestOK := rawBytes(digestValue)
	if !idOK || len(id) != 16 || !digestOK || len(digest) != 32 {
		return nil, nil, false, classified(ErrSchema, stage, ReasonCorrupt)
	}
	return bytes.Clone(id), bytes.Clone(digest), true, nil
}

func (s *Store) expandedPositionToken(ctx context.Context, q queryer, state stateSnapshot, stage Stage) ([32]byte, error) {
	mutation, err := s.reconcileAttemptMutationRevision(ctx, q, stage)
	if err != nil {
		return [32]byte{}, err
	}
	id, digest, active, err := s.currentActiveAttempt(ctx, q, stage)
	if err != nil {
		return [32]byte{}, err
	}
	if !active {
		id, digest = nil, nil
	}
	token, err := makeAttemptToken(s.databaseID, state, mutation, id, digest, s.limits, s.attemptLimits)
	if err != nil {
		return [32]byte{}, classified(ErrSchema, stage, ReasonCorrupt)
	}
	return token, nil
}

func (s *Store) currentToken(ctx context.Context, q queryer, state stateSnapshot, stage Stage) ([32]byte, error) {
	return s.expandedPositionToken(ctx, q, state, stage)
}

func (s *Store) ActiveAttempt(ctx context.Context) (Attempt, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkContext(ctx, StageAttempt); err != nil {
		return Attempt{}, false, err
	}
	if _, err := s.readState(ctx, s.conn, StageAttempt); err != nil {
		return Attempt{}, false, err
	}
	var idLengthValue any
	err := s.conn.QueryRowContext(ctx, "SELECT length(attempt_id) FROM active_publication_attempt WHERE singleton=1").Scan(&idLengthValue)
	if errors.Is(err, sql.ErrNoRows) {
		return Attempt{}, false, nil
	}
	if err != nil {
		return Attempt{}, false, storageFailure(ctx, StageAttempt, err)
	}
	idLength, lengthOK := rawInt64(idLengthValue)
	if !lengthOK || idLength != 16 {
		return Attempt{}, false, classified(ErrSchema, StageAttempt, ReasonCorrupt)
	}
	var id any
	if err := s.conn.QueryRowContext(ctx, "SELECT attempt_id FROM active_publication_attempt WHERE singleton=1").Scan(&id); err != nil {
		return Attempt{}, false, storageFailure(ctx, StageAttempt, err)
	}
	bytesID, ok := rawBytes(id)
	if !ok || len(bytesID) != 16 {
		return Attempt{}, false, classified(ErrSchema, StageAttempt, ReasonCorrupt)
	}
	var attemptID [16]byte
	copy(attemptID[:], bytesID)
	attempt, err := s.loadStoredAttempt(ctx, s.conn, attemptID, StageAttempt)
	if err != nil {
		return Attempt{}, false, err
	}
	projected := projectAttempt(attempt.core, attempt.lifecycle, attempt.outcome, attempt.blocked, attempt.mutationRevision, AvailabilityUnchecked)
	copy(projected.StateDigest[:], attempt.stateDigest)
	return projected, true, nil
}

func (s *Store) LoadAttempt(ctx context.Context, id [16]byte) (Attempt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkContext(ctx, StageAttempt); err != nil {
		return Attempt{}, err
	}
	if _, err := s.readState(ctx, s.conn, StageAttempt); err != nil {
		return Attempt{}, err
	}
	stored, err := s.loadStoredAttempt(ctx, s.conn, id, StageAttempt)
	if err != nil {
		return Attempt{}, err
	}
	projected := projectAttempt(stored.core, stored.lifecycle, stored.outcome, stored.blocked, stored.mutationRevision, AvailabilityUnchecked)
	copy(projected.StateDigest[:], stored.stateDigest)
	return projected, nil
}

func (s *Store) AttemptHistory(ctx context.Context, cursor [16]byte, limit uint32) (AttemptPage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkContext(ctx, StageHistory); err != nil {
		return AttemptPage{}, err
	}
	if limit == 0 || limit > s.attemptLimits.HistoryPageEntries {
		return AttemptPage{}, classified(ErrInvalid, StageHistory, ReasonLimits)
	}
	if _, err := s.readState(ctx, s.conn, StageHistory); err != nil {
		return AttemptPage{}, err
	}
	var afterOrder int64
	if !allZero(cursor[:]) {
		var value any
		if err := s.conn.QueryRowContext(ctx, "SELECT created_order FROM publication_attempts WHERE attempt_id=?", cursor[:]).Scan(&value); err != nil {
			return AttemptPage{}, classified(ErrInvalid, StageHistory, ReasonRecordSet)
		}
		var ok bool
		afterOrder, ok = rawInt64(value)
		if !ok || afterOrder < 0 {
			return AttemptPage{}, classified(ErrSchema, StageHistory, ReasonCorrupt)
		}
	}
	rows, err := s.conn.QueryContext(ctx, "SELECT substr(attempt_id,1,17),length(attempt_id),created_order FROM publication_attempts WHERE created_order>? ORDER BY created_order,attempt_id LIMIT ?", afterOrder, limit+1)
	if err != nil {
		return AttemptPage{}, storageFailure(ctx, StageHistory, err)
	}
	defer rows.Close()
	page := AttemptPage{Attempts: make([]Attempt, 0, limit)}
	var pageBytes uint64
	for rows.Next() {
		var idValue, idLengthValue, orderValue any
		if err := rows.Scan(&idValue, &idLengthValue, &orderValue); err != nil {
			return AttemptPage{}, storageFailure(ctx, StageHistory, err)
		}
		id, idOK := rawBytes(idValue)
		idLength, idLengthOK := rawInt64(idLengthValue)
		order, orderOK := rawInt64(orderValue)
		if !idOK || !idLengthOK || idLength != 16 || len(id) != 16 || !orderOK || order < 0 {
			return AttemptPage{}, classified(ErrSchema, StageHistory, ReasonCorrupt)
		}
		if len(page.Attempts) >= int(limit) {
			page.HasMore = true
			break
		}
		var attemptID [16]byte
		copy(attemptID[:], id)
		stored, err := s.loadStoredAttempt(ctx, s.conn, attemptID, StageHistory)
		if err != nil {
			return AttemptPage{}, err
		}
		attempt := projectAttempt(stored.core, stored.lifecycle, stored.outcome, stored.blocked, stored.mutationRevision, AvailabilityUnchecked)
		copy(attempt.StateDigest[:], stored.stateDigest)
		encoded, err := canonicalJSON(attempt)
		if err != nil || uint64(len(encoded)) > s.attemptLimits.HistoryPageBytes {
			return AttemptPage{}, classified(ErrLimit, StageHistory, ReasonCapacity)
		}
		evidenceRows, err := s.conn.QueryContext(ctx, "SELECT role,body FROM attempt_evidence WHERE attempt_id=? ORDER BY role", attemptID[:])
		if err != nil {
			return AttemptPage{}, storageFailure(ctx, StageHistory, err)
		}
		entryEvidence := make([]AttemptEvidence, 0)
		entryBytes := uint64(len(encoded))
		for evidenceRows.Next() {
			var roleValue, bodyValue any
			if err := evidenceRows.Scan(&roleValue, &bodyValue); err != nil {
				_ = evidenceRows.Close()
				return AttemptPage{}, storageFailure(ctx, StageHistory, err)
			}
			role, roleOK := roleValue.(string)
			body, bodyOK := rawBytes(bodyValue)
			if !roleOK || !bodyOK {
				_ = evidenceRows.Close()
				return AttemptPage{}, classified(ErrSchema, StageHistory, ReasonCorrupt)
			}
			entryEvidence = append(entryEvidence, AttemptEvidence{AttemptID: attemptID, Role: role, Evidence: bytes.Clone(body)})
			entryBytes += uint64(len(body) + 32)
		}
		if err := evidenceRows.Err(); err != nil {
			_ = evidenceRows.Close()
			return AttemptPage{}, storageFailure(ctx, StageHistory, err)
		}
		if err := evidenceRows.Close(); err != nil {
			return AttemptPage{}, storageFailure(ctx, StageHistory, err)
		}
		var dispatchLengthValue any
		if err := s.conn.QueryRowContext(ctx, "SELECT length(body) FROM attempt_events WHERE attempt_id=? AND kind='may-have-submitted'", attemptID[:]).Scan(&dispatchLengthValue); err == nil {
			dispatchLength, ok := rawInt64(dispatchLengthValue)
			if !ok || dispatchLength <= 0 || uint64(dispatchLength) > s.attemptLimits.EventBytes {
				return AttemptPage{}, classified(ErrSchema, StageHistory, ReasonCorrupt)
			}
			var dispatchValue any
			if err := s.conn.QueryRowContext(ctx, "SELECT body FROM attempt_events WHERE attempt_id=? AND kind='may-have-submitted'", attemptID[:]).Scan(&dispatchValue); err != nil {
				return AttemptPage{}, storageFailure(ctx, StageHistory, err)
			}
			dispatchBody, ok := rawBytes(dispatchValue)
			var event attemptEventWire
			if !ok || strictJSON(dispatchBody, &event) != nil || len(event.Evidence) == 0 {
				return AttemptPage{}, classified(ErrSchema, StageHistory, ReasonCorrupt)
			}
			entryEvidence = append(entryEvidence, AttemptEvidence{AttemptID: attemptID, Role: "submission", Evidence: bytes.Clone(event.Evidence)})
			entryBytes += uint64(len(event.Evidence) + 32)
		} else if !errors.Is(err, sql.ErrNoRows) {
			return AttemptPage{}, storageFailure(ctx, StageHistory, err)
		}
		if pageBytes+entryBytes > s.attemptLimits.HistoryPageBytes {
			if len(page.Attempts) == 0 {
				return AttemptPage{}, classified(ErrLimit, StageHistory, ReasonCapacity)
			}
			page.HasMore = true
			break
		}
		pageBytes += entryBytes
		page.Attempts = append(page.Attempts, attempt)
		page.Evidence = append(page.Evidence, entryEvidence...)
		page.NextID = attemptID
	}
	if err := rows.Err(); err != nil {
		return AttemptPage{}, storageFailure(ctx, StageHistory, err)
	}
	return page, nil
}

func (s *Store) ReadCandidate(ctx context.Context, id [16]byte) (CandidateMaterial, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkContext(ctx, StageCustody); err != nil {
		return CandidateMaterial{}, err
	}
	if _, err := s.readState(ctx, s.conn, StageCustody); err != nil {
		return CandidateMaterial{}, err
	}
	stored, err := s.loadStoredAttempt(ctx, s.conn, id, StageCustody)
	if err != nil {
		return CandidateMaterial{}, err
	}
	if err := s.openPayloadDirectoryForRead(); err != nil {
		return CandidateMaterial{}, classifyCandidateDirectory(err, StageCustody)
	}
	var basename string
	var sizeValue any
	if err := s.conn.QueryRowContext(ctx, "SELECT basename,size FROM (SELECT payload_objects.basename,payload_objects.size FROM attempt_payload_refs JOIN payload_objects USING(blob_cid) WHERE attempt_payload_refs.attempt_id=? UNION ALL SELECT payload_objects.basename,payload_objects.size FROM retained_publications JOIN payload_objects USING(blob_cid) WHERE retained_publications.attempt_id=?) LIMIT 1", id[:], id[:]).Scan(&basename, &sizeValue); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return CandidateMaterial{}, classified(ErrStorage, StageCustody, ReasonCandidateMissing)
		}
		return CandidateMaterial{}, storageFailure(ctx, StageCustody, err)
	}
	size, ok := rawInt64(sizeValue)
	if !ok || size <= 0 || uint64(size) != stored.core.BlobSize {
		return CandidateMaterial{}, classified(ErrSchema, StageCustody, ReasonCorrupt)
	}
	blob := publication.BlobReference{CID: bytes.Clone(stored.core.BlobCID), Size: stored.core.BlobSize}
	data, err := s.inspectPayloadFile(basename, nil, blob)
	if err != nil {
		return CandidateMaterial{}, classifyCandidateRead(err, StageCustody)
	}
	return CandidateMaterial{AttemptID: id, SnapshotKey: stored.core.SnapshotKey, SnapshotRecord: bytes.Clone(stored.core.SnapshotRecord), HeadRecord: bytes.Clone(stored.core.HeadRecord), Payload: data, Blob: blob}, nil
}

func classifyCandidateDirectory(err error, stage Stage) error {
	if errors.Is(err, unix.ENOENT) {
		return classified(ErrStorage, stage, ReasonCandidateMissing)
	}
	if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
		return classified(ErrStorage, stage, ReasonCandidateUnsafe)
	}
	return classified(ErrStorage, stage, ReasonIO)
}

func classifyCandidateRead(err error, stage Stage) error {
	if errors.Is(err, unix.ENOENT) {
		return classified(ErrStorage, stage, ReasonCandidateMissing)
	}
	if errors.Is(err, errUnsafePayloadObject) || errors.Is(err, unix.ELOOP) {
		return classified(ErrStorage, stage, ReasonCandidateUnsafe)
	}
	if errors.Is(err, errCorruptPayloadObject) || errors.Is(err, io.ErrUnexpectedEOF) {
		return classified(ErrStorage, stage, ReasonCandidateCorrupt)
	}
	return classified(ErrStorage, stage, ReasonIO)
}

func projectAttempt(core attemptCoreWire, lifecycle AttemptLifecycle, outcome AttemptOutcome, blocked string, mutation uint64, availability AttemptAvailability) Attempt {
	var id [16]byte
	copy(id[:], core.AttemptID)
	var floor *Floor
	if core.CapturedFloor != nil {
		decoded, err := floorFromWire(*core.CapturedFloor)
		if err == nil {
			floor = &decoded
		}
	}
	snapshot, _ := publication.DecodeSnapshot(core.SnapshotRecord)
	return Attempt{ID: id, Kind: AttemptKind(core.Kind), Lifecycle: lifecycle, Outcome: outcome, Blocked: blocked, Sequence: snapshot.PublicationSeq, SnapshotKey: core.SnapshotKey, SnapshotRecordCID: bytes.Clone(core.SnapshotCID), HeadRecordCID: bytes.Clone(core.HeadCID), BlobCID: bytes.Clone(core.BlobCID), BlobSize: core.BlobSize, CapturedFloor: floor, CapturedRevision: core.CapturedRevision, CapturedGeneration: core.CapturedGeneration, MutationRevision: mutation, Availability: availability}
}

func rawNullableInt64(value any) (int64, bool) {
	if value == nil {
		return 0, true
	}
	return rawInt64(value)
}

func (s *Store) loadStoredAttempt(ctx context.Context, q queryer, id [16]byte, stage Stage) (storedAttempt, error) {
	var coreLengthValue, digestLengthValue, lifecycleLengthValue, outcomeLengthValue, blockedLengthValue, terminalLengthValue, retirementLengthValue any
	err := q.QueryRowContext(ctx, "SELECT length(core),length(state_digest),length(lifecycle),length(outcome),length(blocked),length(terminal_evidence),length(retirement_evidence) FROM publication_attempts WHERE attempt_id=?", id[:]).Scan(&coreLengthValue, &digestLengthValue, &lifecycleLengthValue, &outcomeLengthValue, &blockedLengthValue, &terminalLengthValue, &retirementLengthValue)
	if errors.Is(err, sql.ErrNoRows) {
		return storedAttempt{}, classified(ErrInvalid, stage, ReasonRecordSet)
	}
	if err != nil {
		return storedAttempt{}, storageFailure(ctx, stage, err)
	}
	coreLength, coreLengthOK := rawInt64(coreLengthValue)
	digestLength, digestLengthOK := rawInt64(digestLengthValue)
	lifecycleLength, lifecycleLengthOK := rawInt64(lifecycleLengthValue)
	outcomeLength, outcomeLengthOK := rawInt64(outcomeLengthValue)
	blockedLength, blockedLengthOK := rawInt64(blockedLengthValue)
	terminalLength, terminalLengthOK := rawNullableInt64(terminalLengthValue)
	retirementLength, retirementLengthOK := rawNullableInt64(retirementLengthValue)
	if !coreLengthOK || !digestLengthOK || !lifecycleLengthOK || !outcomeLengthOK || !blockedLengthOK || !terminalLengthOK || !retirementLengthOK || coreLength <= 0 || uint64(coreLength) > s.attemptLimits.CoreBytes || digestLength != 32 || lifecycleLength <= 0 || lifecycleLength > 64 || outcomeLength <= 0 || outcomeLength > 64 || blockedLength < 0 || blockedLength > 64 || terminalLength < 0 || uint64(terminalLength) > s.attemptLimits.EvidenceSlotBytes || retirementLength < 0 || uint64(retirementLength) > s.attemptLimits.EvidenceSlotBytes {
		return storedAttempt{}, classified(ErrSchema, stage, ReasonCorrupt)
	}
	var coreValue, stateValue, lifecycleValue, outcomeValue, blockedValue, mutationValue, orderValue, logicalValue, terminalValue, retirementValue any
	err = q.QueryRowContext(ctx, "SELECT core,state_digest,lifecycle,outcome,blocked,mutation_revision,created_order,logical_bytes,terminal_evidence,retirement_evidence FROM publication_attempts WHERE attempt_id=?", id[:]).Scan(&coreValue, &stateValue, &lifecycleValue, &outcomeValue, &blockedValue, &mutationValue, &orderValue, &logicalValue, &terminalValue, &retirementValue)
	if err != nil {
		return storedAttempt{}, storageFailure(ctx, stage, err)
	}
	coreBytes, coreOK := rawBytes(coreValue)
	stateDigest, digestOK := rawBytes(stateValue)
	lifecycleText, lifecycleOK := lifecycleValue.(string)
	outcomeText, outcomeOK := outcomeValue.(string)
	blocked, blockedOK := blockedValue.(string)
	mutation, mutationOK := rawInt64(mutationValue)
	order, orderOK := rawInt64(orderValue)
	logicalBytes, logicalOK := rawInt64(logicalValue)
	terminal, terminalOK := rawNullableBytes(terminalValue)
	retirement, retirementOK := rawNullableBytes(retirementValue)
	if !coreOK || !digestOK || !lifecycleOK || !outcomeOK || !blockedOK || !mutationOK || !orderOK || !logicalOK || !terminalOK || !retirementOK || len(stateDigest) != 32 || mutation <= 0 || order <= 0 || mutation < order || logicalBytes < 0 {
		return storedAttempt{}, classified(ErrSchema, stage, ReasonCorrupt)
	}
	core, err := decodeAttemptCore(coreBytes)
	if err != nil || !bytes.Equal(core.AttemptID, id[:]) || !bytes.Equal(core.DatabaseID, s.databaseID[:]) {
		return storedAttempt{}, classified(ErrSchema, stage, ReasonCorrupt)
	}
	lifecycle := AttemptLifecycle(lifecycleText)
	outcome := AttemptOutcome(outcomeText)
	if !validLifecycle(lifecycle) || !validOutcome(outcome) || (blocked != "" && blocked != "blocked-floor-replaced") || ((lifecycle == AttemptPrepared || lifecycle == AttemptUploadStarted) && outcome != OutcomeNotSubmitted) || (lifecycle == AttemptRetiredSuccess && outcome != OutcomeCurrent) || (lifecycle == AttemptRetiredAbandoned && outcome == OutcomeUnresolved) {
		return storedAttempt{}, classified(ErrSchema, stage, ReasonCorrupt)
	}
	calculated, err := makeAttemptStateDigest(coreBytes, lifecycle, outcome, blocked, uint64(mutation), terminal, retirement)
	if err != nil || !bytes.Equal(calculated[:], stateDigest) {
		return storedAttempt{}, classified(ErrSchema, stage, ReasonCorrupt)
	}
	if err := validateStoredAttemptCore(core, s.binding, s.limits, s.databaseID); err != nil {
		return storedAttempt{}, classified(ErrSchema, stage, ReasonCorrupt)
	}
	return storedAttempt{core: core, coreBytes: bytes.Clone(coreBytes), lifecycle: lifecycle, outcome: outcome, blocked: blocked, stateDigest: bytes.Clone(stateDigest), mutationRevision: uint64(mutation), createdOrder: uint64(order), logicalBytes: uint64(logicalBytes), terminal: bytes.Clone(terminal), retirement: bytes.Clone(retirement)}, nil
}

func validateStoredAttemptCore(core attemptCoreWire, binding Binding, limits Limits, databaseID [32]byte) error {
	storedBinding, err := bindingFromWire(core.Binding)
	if err != nil || !sameBinding(storedBinding, binding) || core.Version != 1 || len(core.AttemptID) != 16 || len(core.DatabaseID) != 32 || !bytes.Equal(core.DatabaseID, databaseID[:]) || len(core.BlobCID) == 0 || core.BlobSize == 0 || core.BlobSize > publication.MaxBlobBytes || len(core.CandidateConfirmation) != 32 || core.ReservedCompletionBytes != 512<<10 || len(core.Review.SelectionDigest) != 32 || len(core.Review.ApprovalDigest) != 32 || allZero(core.Review.SelectionDigest) || allZero(core.Review.ApprovalDigest) || core.Review.SelectionRevision == 0 || core.Review.ApprovalRevision == 0 {
		return errors.New("core")
	}
	snapshot, err := publication.DecodeSnapshot(core.SnapshotRecord)
	if err != nil || snapshot.Vault != binding.Vault || snapshot.PublicationSeq >= ordinaryPublicationLimit || !bytes.Equal(snapshot.PublicationID[:], core.AttemptID) || !bytes.Equal(snapshot.Blob.CID, core.BlobCID) || snapshot.Blob.Size != core.BlobSize {
		return errors.New("snapshot")
	}
	initialContext, err := contextFromWire(core.InitialContext)
	if err != nil || validateContext(initialContext, binding, limits) != nil {
		return errors.New("initial context")
	}
	if key, err := publication.SequenceKey(snapshot.PublicationSeq); err != nil || key != core.SnapshotKey {
		return errors.New("key")
	}
	snapshotCID, err := publication.RecordCID(core.SnapshotRecord)
	if err != nil || !bytes.Equal(snapshotCID, core.SnapshotCID) {
		return errors.New("snapshot cid")
	}
	head, err := publication.DecodeHead(core.HeadRecord)
	if err != nil || head.Vault != binding.Vault || !bytes.Equal(head.SnapshotCID, core.SnapshotCID) || !bytes.Equal(head.BlobCID, core.BlobCID) || head.PublicationSeq != snapshot.PublicationSeq || publication.VerifyHeadBinding(core.HeadRecord, core.SnapshotRecord, core.SnapshotKey) != nil {
		return errors.New("head")
	}
	headCID, err := publication.RecordCID(core.HeadRecord)
	if err != nil || !bytes.Equal(headCID, core.HeadCID) {
		return errors.New("head cid")
	}
	if core.Kind == string(AttemptGenesis) {
		if snapshot.PublicationSeq != 0 || core.CapturedFloor != nil || core.CapturedRevision != 0 || core.CapturedGeneration != 0 || len(core.PredecessorRecord) != 0 || len(core.PredecessorCID) != 0 || core.PredecessorKey != "" {
			return errors.New("genesis")
		}
	} else if core.Kind == string(AttemptSuccessor) {
		if core.CapturedFloor == nil || len(core.PredecessorRecord) == 0 || len(core.PredecessorCID) == 0 || core.PredecessorKey == "" {
			return errors.New("successor")
		}
		floor, err := floorFromWire(*core.CapturedFloor)
		if err != nil || !sameBinding(floor.Binding, binding) || floor.DatabaseID != databaseID || floor.Revision != core.CapturedRevision || floor.Generation != core.CapturedGeneration || floor.Sequence+1 != snapshot.PublicationSeq || !bytes.Equal(floor.RecordCID, core.PredecessorCID) || floor.SnapshotKey != core.PredecessorKey {
			return errors.New("predecessor")
		}
		if err := publication.VerifySuccessor(core.PredecessorRecord, core.SnapshotRecord, core.SnapshotKey); err != nil {
			return errors.New("successor record")
		}
		predecessorCID, err := publication.RecordCID(core.PredecessorRecord)
		if err != nil || !bytes.Equal(predecessorCID, core.PredecessorCID) {
			return errors.New("predecessor cid")
		}
	} else {
		return errors.New("kind")
	}
	return nil
}

func (s *Store) checkAttemptGraph(ctx context.Context, q queryer, stage Stage) error {
	var activeCountValue, attemptsCountValue, metadataValue, evidenceValue, retainedValue, payloadValue any
	for query, destination := range map[string]*any{
		"SELECT COUNT(*) FROM active_publication_attempt":                           &activeCountValue,
		"SELECT COUNT(*) FROM publication_attempts":                                 &attemptsCountValue,
		"SELECT COALESCE(SUM(logical_bytes),0) FROM publication_attempts":           &metadataValue,
		"SELECT COALESCE(SUM(length(body)+length(digest)),0) FROM attempt_evidence": &evidenceValue,
		"SELECT COUNT(*) FROM retained_publications":                                &retainedValue,
		"SELECT COUNT(*) FROM payload_objects":                                      &payloadValue,
	} {
		if err := q.QueryRowContext(ctx, query).Scan(destination); err != nil {
			return storageFailure(ctx, stage, err)
		}
	}
	activeCount, activeOK := rawInt64(activeCountValue)
	attemptCount, attemptOK := rawInt64(attemptsCountValue)
	metadataBytes, metadataOK := rawInt64(metadataValue)
	evidenceBytes, evidenceOK := rawInt64(evidenceValue)
	retainedCount, retainedOK := rawInt64(retainedValue)
	payloadCount, payloadOK := rawInt64(payloadValue)
	if !activeOK || !attemptOK || !metadataOK || !evidenceOK || !retainedOK || !payloadOK || activeCount < 0 || attemptCount < 0 || metadataBytes < 0 || evidenceBytes < 0 || retainedCount < 0 || payloadCount < 0 || uint64(activeCount) > uint64(s.attemptLimits.ActiveAttempts) || uint64(attemptCount) > uint64(s.attemptLimits.HistoricalAttempts) || uint64(metadataBytes) > s.attemptLimits.MetadataBytes || uint64(evidenceBytes) > s.attemptLimits.EvidenceBytes || uint64(retainedCount) > uint64(s.attemptLimits.RetainedPublications) || uint64(payloadCount) > uint64(s.attemptLimits.ManagedObjects) {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	mutation, err := s.reconcileAttemptMutationRevision(ctx, q, stage)
	if err != nil {
		return err
	}
	catalogRows, err := q.QueryContext(ctx, "SELECT substr(blob_cid,1,129),length(blob_cid),size,substr(basename,1,73),length(basename),logical_bytes FROM payload_objects")
	if err != nil {
		return storageFailure(ctx, stage, err)
	}
	var cataloguedBytes uint64
	for catalogRows.Next() {
		var cidValue, cidLengthValue, sizeValue, nameValue, nameLengthValue, logicalValue any
		if err := catalogRows.Scan(&cidValue, &cidLengthValue, &sizeValue, &nameValue, &nameLengthValue, &logicalValue); err != nil {
			_ = catalogRows.Close()
			return storageFailure(ctx, stage, err)
		}
		blobCID, cidOK := rawBytes(cidValue)
		cidLength, cidLengthOK := rawInt64(cidLengthValue)
		size, sizeOK := rawInt64(sizeValue)
		name, nameOK := nameValue.(string)
		nameLength, nameLengthOK := rawInt64(nameLengthValue)
		logical, logicalOK := rawInt64(logicalValue)
		wantedName, nameErr := payloadBasenameFromCID(blobCID)
		if !cidOK || !cidLengthOK || cidLength <= 0 || cidLength > publication.MaxCIDBytes || int64(len(blobCID)) != cidLength || !sizeOK || size <= 0 || uint64(size) > publication.MaxBlobBytes || !nameOK || !nameLengthOK || nameLength != 72 || int64(len(name)) != nameLength || !logicalOK || logical != size || nameErr != nil || wantedName != name {
			_ = catalogRows.Close()
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
		cataloguedBytes += uint64(size)
	}
	if err := catalogRows.Err(); err != nil {
		_ = catalogRows.Close()
		return storageFailure(ctx, stage, err)
	}
	if err := catalogRows.Close(); err != nil {
		return storageFailure(ctx, stage, err)
	}
	if cataloguedBytes > s.attemptLimits.CustodyBytes {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	rows, err := q.QueryContext(ctx, "SELECT substr(attempt_id,1,17),length(attempt_id) FROM publication_attempts ORDER BY created_order,attempt_id")
	if err != nil {
		return storageFailure(ctx, stage, err)
	}
	attempts := make(map[[16]byte]storedAttempt)
	for rows.Next() {
		var idValue, idLengthValue any
		if err := rows.Scan(&idValue, &idLengthValue); err != nil {
			_ = rows.Close()
			return storageFailure(ctx, stage, err)
		}
		idBytes, valid := rawBytes(idValue)
		idLength, lengthValid := rawInt64(idLengthValue)
		if !valid || !lengthValid || idLength != 16 || len(idBytes) != 16 {
			_ = rows.Close()
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
		var id [16]byte
		copy(id[:], idBytes)
		stored, err := s.loadStoredAttempt(ctx, q, id, stage)
		if err != nil || uint64(len(stored.coreBytes)) > s.attemptLimits.CoreBytes || stored.mutationRevision > mutation {
			_ = rows.Close()
			if err != nil {
				return err
			}
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
		if err := s.validateAttemptJournal(ctx, q, stored, stage); err != nil {
			_ = rows.Close()
			return err
		}
		attempts[id] = stored
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return storageFailure(ctx, stage, err)
	}
	if err := rows.Close(); err != nil {
		return storageFailure(ctx, stage, err)
	}
	var activeIDValue, activeIDLengthValue any
	activeErr := q.QueryRowContext(ctx, "SELECT substr(attempt_id,1,17),length(attempt_id) FROM active_publication_attempt WHERE singleton=1").Scan(&activeIDValue, &activeIDLengthValue)
	var activeID [16]byte
	if activeCount == 0 {
		if !errors.Is(activeErr, sql.ErrNoRows) {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
	} else {
		if activeErr != nil {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
		idBytes, ok := rawBytes(activeIDValue)
		idLength, lengthOK := rawInt64(activeIDLengthValue)
		if !ok || !lengthOK || idLength != 16 || len(idBytes) != 16 {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
		copy(activeID[:], idBytes)
	}
	var nonretired int
	for id, attempt := range attempts {
		var refCount, reservationCount, retainedRows int64
		if err := q.QueryRowContext(ctx, "SELECT COUNT(*) FROM attempt_payload_refs WHERE attempt_id=?", id[:]).Scan(&refCount); err != nil {
			return storageFailure(ctx, stage, err)
		}
		if err := q.QueryRowContext(ctx, "SELECT COUNT(*) FROM attempt_reservations WHERE attempt_id=?", id[:]).Scan(&reservationCount); err != nil {
			return storageFailure(ctx, stage, err)
		}
		if err := q.QueryRowContext(ctx, "SELECT COUNT(*) FROM retained_publications WHERE attempt_id=?", id[:]).Scan(&retainedRows); err != nil {
			return storageFailure(ctx, stage, err)
		}
		active := attempt.lifecycle != AttemptRetiredAbandoned && attempt.lifecycle != AttemptRetiredSuccess
		if active {
			nonretired++
			if activeCount != 1 || id != activeID || refCount != 1 || reservationCount != 1 || retainedRows != 0 {
				return classified(ErrSchema, stage, ReasonCorrupt)
			}
			if err := s.validateAttemptPayloadReference(ctx, q, attempt, stage); err != nil {
				return err
			}
		} else if refCount != 0 || reservationCount != 0 {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
		if attempt.lifecycle == AttemptRetiredSuccess {
			if attempt.outcome != OutcomeCurrent || retainedRows != 1 {
				return classified(ErrSchema, stage, ReasonCorrupt)
			}
			if err := s.validateRetainedPublication(ctx, q, attempt, stage); err != nil {
				return err
			}
		} else if retainedRows != 0 {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
	}
	if nonretired != int(activeCount) {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	reservationRows, err := q.QueryContext(ctx, "SELECT substr(attempt_id,1,17),length(attempt_id),metadata_bytes,accepted_bytes,accepted_records,accepted_events,retained_points FROM attempt_reservations")
	if err != nil {
		return storageFailure(ctx, stage, err)
	}
	reservationCount := 0
	for reservationRows.Next() {
		var idValue, idLengthValue, metadataValue, acceptedBytesValue, acceptedRecordsValue, acceptedEventsValue, retainedValue any
		if err := reservationRows.Scan(&idValue, &idLengthValue, &metadataValue, &acceptedBytesValue, &acceptedRecordsValue, &acceptedEventsValue, &retainedValue); err != nil {
			_ = reservationRows.Close()
			return storageFailure(ctx, stage, err)
		}
		id, idOK := rawBytes(idValue)
		idLength, idLengthOK := rawInt64(idLengthValue)
		metadata, metadataOK := rawInt64(metadataValue)
		acceptedBytes, acceptedBytesOK := rawInt64(acceptedBytesValue)
		acceptedRecords, acceptedRecordsOK := rawInt64(acceptedRecordsValue)
		acceptedEvents, acceptedEventsOK := rawInt64(acceptedEventsValue)
		retained, retainedOK := rawInt64(retainedValue)
		activeAttempt, activeExists := attempts[activeID]
		wantAcceptedBytes, wantAcceptedRecords, wantAcceptedEvents, wantRetained := int64(512<<10), int64(2), int64(1), int64(1)
		if activeExists && activeAttempt.blocked == "blocked-floor-replaced" {
			wantAcceptedBytes, wantAcceptedRecords, wantAcceptedEvents, wantRetained = 0, 0, 0, 0
		}
		if !idOK || !idLengthOK || idLength != 16 || len(id) != 16 || !metadataOK || !acceptedBytesOK || !acceptedRecordsOK || !acceptedEventsOK || !retainedOK || metadata < 0 || acceptedBytes < 0 || acceptedRecords < 0 || acceptedEvents < 0 || retained < 0 || activeCount != 1 || !bytes.Equal(id, activeID[:]) || uint64(metadata) != s.attemptReservationSize() || acceptedBytes != wantAcceptedBytes || acceptedRecords != wantAcceptedRecords || acceptedEvents != wantAcceptedEvents || retained != wantRetained {
			_ = reservationRows.Close()
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
		reservationCount++
	}
	if err := reservationRows.Err(); err != nil {
		_ = reservationRows.Close()
		return storageFailure(ctx, stage, err)
	}
	if err := reservationRows.Close(); err != nil {
		return storageFailure(ctx, stage, err)
	}
	if reservationCount != int(activeCount) {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	var pendingCount int64
	if err := q.QueryRowContext(ctx, "SELECT COUNT(*) FROM pending_genesis").Scan(&pendingCount); err != nil {
		return storageFailure(ctx, stage, err)
	}
	if activeCount == 0 {
		if pendingCount != 0 {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
	} else {
		active := attempts[activeID]
		if active.core.Kind == string(AttemptGenesis) {
			var pendingIDValue, pendingIDLengthValue, vaultValue, vaultLengthValue any
			if pendingCount != 1 || q.QueryRowContext(ctx, "SELECT substr(attempt_id,1,17),length(attempt_id),substr(vault,1,33),length(vault) FROM pending_genesis WHERE singleton=1").Scan(&pendingIDValue, &pendingIDLengthValue, &vaultValue, &vaultLengthValue) != nil {
				return classified(ErrSchema, stage, ReasonCorrupt)
			}
			pendingID, idOK := rawBytes(pendingIDValue)
			pendingIDLength, pendingLengthOK := rawInt64(pendingIDLengthValue)
			vault, vaultOK := rawBytes(vaultValue)
			vaultLength, vaultLengthOK := rawInt64(vaultLengthValue)
			if !idOK || !pendingLengthOK || pendingIDLength != 16 || !bytes.Equal(pendingID, activeID[:]) || !vaultOK || !vaultLengthOK || vaultLength != 32 || !bytes.Equal(vault, s.binding.Vault[:]) {
				return classified(ErrSchema, stage, ReasonCorrupt)
			}
		} else if pendingCount != 0 {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
	}
	var foreignRows *sql.Rows
	foreignRows, err = q.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return storageFailure(ctx, stage, err)
	}
	if foreignRows.Next() {
		_ = foreignRows.Close()
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	if err := foreignRows.Err(); err != nil {
		_ = foreignRows.Close()
		return storageFailure(ctx, stage, err)
	}
	if err := foreignRows.Close(); err != nil {
		return storageFailure(ctx, stage, err)
	}
	return nil
}

type attemptEventMeta struct {
	ordinal uint32
	kind    string
}

func (s *Store) validateAttemptJournal(ctx context.Context, q queryer, attempt storedAttempt, stage Stage) error {
	rows, err := q.QueryContext(ctx, "SELECT ordinal,substr(kind,1,65),length(kind),length(body),length(digest) FROM attempt_events WHERE attempt_id=? ORDER BY ordinal LIMIT ?", attempt.core.AttemptID, s.attemptLimits.LifecycleEvents+1)
	if err != nil {
		return storageFailure(ctx, stage, err)
	}
	events := make([]attemptEventMeta, 0, s.attemptLimits.LifecycleEvents)
	var expectedOrdinal int64 = 1
	for rows.Next() {
		var ordinalValue, kindValue, kindLengthValue, bodyLengthValue, digestLengthValue any
		if err := rows.Scan(&ordinalValue, &kindValue, &kindLengthValue, &bodyLengthValue, &digestLengthValue); err != nil {
			_ = rows.Close()
			return storageFailure(ctx, stage, err)
		}
		ordinal, ordinalOK := rawInt64(ordinalValue)
		kind, kindOK := kindValue.(string)
		kindLength, kindLengthOK := rawInt64(kindLengthValue)
		bodyLength, bodyLengthOK := rawInt64(bodyLengthValue)
		digestLength, digestLengthOK := rawInt64(digestLengthValue)
		if !ordinalOK || ordinal != expectedOrdinal || !kindOK || !kindLengthOK || kindLength <= 0 || kindLength > 64 || !validAttemptEventKind(kind) || !bodyLengthOK || bodyLength <= 0 || uint64(bodyLength) > s.attemptLimits.EventBytes || !digestLengthOK || digestLength != 32 || uint32(len(events)) >= s.attemptLimits.LifecycleEvents {
			_ = rows.Close()
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
		events = append(events, attemptEventMeta{ordinal: uint32(ordinal), kind: kind})
		expectedOrdinal++
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return storageFailure(ctx, stage, err)
	}
	if err := rows.Close(); err != nil {
		return storageFailure(ctx, stage, err)
	}
	var previous []byte
	var eventBytes uint64
	kinds := make([]string, 0, len(events))
	for _, metadata := range events {
		var bodyValue, digestValue any
		if err := q.QueryRowContext(ctx, "SELECT body,digest FROM attempt_events WHERE attempt_id=? AND ordinal=?", attempt.core.AttemptID, metadata.ordinal).Scan(&bodyValue, &digestValue); err != nil {
			return storageFailure(ctx, stage, err)
		}
		body, bodyOK := rawBytes(bodyValue)
		digest, digestOK := rawBytes(digestValue)
		if !bodyOK || !digestOK || len(body) == 0 || uint64(len(body)) > s.attemptLimits.EventBytes || len(digest) != 32 {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
		var wire attemptEventWire
		if strictJSON(body, &wire) != nil || wire.Version != 1 || wire.Ordinal != metadata.ordinal || wire.Kind != metadata.kind || !bytes.Equal(wire.PreviousDigest, previous) || len(wire.StateDigest) != 32 {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
		if metadata.kind == "may-have-submitted" {
			var dispatchEvidence attemptEvidenceWire
			if len(wire.Evidence) == 0 || uint64(len(wire.Evidence)) > s.attemptLimits.EventBytes || strictJSON(wire.Evidence, &dispatchEvidence) != nil || dispatchEvidence.Version != 1 || s.validateAttemptEvidenceWire(attempt, "submission", dispatchEvidence) != nil {
				return classified(ErrSchema, stage, ReasonCorrupt)
			}
		} else if metadata.kind == "outcome-lost-fence" {
			if len(wire.Evidence) != 32 {
				return classified(ErrSchema, stage, ReasonCorrupt)
			}
		} else if len(wire.Evidence) != 0 {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
		calculated := domainHash("systems.lamb.dottie.publication-attempt-event.v1", body)
		if !bytes.Equal(calculated[:], digest) {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
		eventBytes += uint64(len(body) + len(digest))
		previous = bytes.Clone(digest)
		kinds = append(kinds, metadata.kind)
	}
	if len(kinds) == 0 || kinds[0] != "created" || countEventKind(kinds, "created") != 1 || countEventKind(kinds, "upload-started") > 1 || countEventKind(kinds, "may-have-submitted") > 1 || countEventKind(kinds, "blocked-floor-replaced") > 1 || countEventKind(kinds, "retired-success") > 1 || countEventKind(kinds, "retired-abandoned") > 1 || countEventKind(kinds, "outcome-lost-fence") > 1 {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	if (attempt.lifecycle == AttemptUploadStarted || attempt.lifecycle == AttemptMayHaveSubmitted || attempt.lifecycle == AttemptRetiredSuccess || (attempt.lifecycle == AttemptRetiredAbandoned && countEventKind(kinds, "may-have-submitted") == 1)) && countEventKind(kinds, "upload-started") != 1 {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	if attempt.lifecycle == AttemptPrepared && countEventKind(kinds, "upload-started") != 0 {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	if (attempt.lifecycle == AttemptMayHaveSubmitted || attempt.lifecycle == AttemptRetiredSuccess || (attempt.lifecycle == AttemptRetiredAbandoned && attempt.outcome != OutcomeNotSubmitted)) && countEventKind(kinds, "may-have-submitted") != 1 {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	if (attempt.lifecycle == AttemptRetiredSuccess) != (countEventKind(kinds, "retired-success") == 1) || (attempt.lifecycle == AttemptRetiredAbandoned) != (countEventKind(kinds, "retired-abandoned") == 1) || (attempt.blocked == "blocked-floor-replaced") != (countEventKind(kinds, "blocked-floor-replaced") == 1) {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	if err := validateAttemptJournalProjection(kinds, attempt, stage); err != nil {
		return err
	}
	if attempt.core.CandidateConfirmation == nil {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	if err := s.validateAttemptEvidenceRows(ctx, q, attempt, stage); err != nil {
		return err
	}
	var evidenceBytes any
	if err := q.QueryRowContext(ctx, "SELECT COALESCE(SUM(length(body)+length(digest)),0) FROM attempt_evidence WHERE attempt_id=?", attempt.core.AttemptID).Scan(&evidenceBytes); err != nil {
		return storageFailure(ctx, stage, err)
	}
	evidence, ok := rawInt64(evidenceBytes)
	if !ok || evidence < 0 || attempt.logicalBytes != uint64(len(attempt.coreBytes))+eventBytes+uint64(evidence) {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	return nil
}

func countEventKind(kinds []string, target string) uint32 {
	var count uint32
	for _, kind := range kinds {
		if kind == target {
			count++
		}
	}
	return count
}

var attemptEventKinds = [...]string{"created", "upload-started", "may-have-submitted", "blocked-floor-replaced", "retired-success", "retired-abandoned", "outcome-observed-absent-unresolved", "outcome-observed-current", "outcome-committed-superseded", "outcome-lost-fence", "outcome-unresolved", "outcome-not-submitted"}

func validAttemptEventKind(kind string) bool {
	for _, candidate := range attemptEventKinds {
		if kind == candidate {
			return true
		}
	}
	return false
}

func maximumAttemptEventKind() string {
	maximum := attemptEventKinds[0]
	for _, candidate := range attemptEventKinds[1:] {
		if len(candidate) > len(maximum) {
			maximum = candidate
		}
	}
	return maximum
}

type attemptEvidenceMeta struct {
	role string
}

func (s *Store) validateAttemptEvidenceRows(ctx context.Context, q queryer, attempt storedAttempt, stage Stage) error {
	rows, err := q.QueryContext(ctx, "SELECT substr(role,1,17),length(role),length(body),length(digest) FROM attempt_evidence WHERE attempt_id=? ORDER BY role LIMIT 4", attempt.core.AttemptID)
	if err != nil {
		return storageFailure(ctx, stage, err)
	}
	metadata := make([]attemptEvidenceMeta, 0, 3)
	for rows.Next() {
		var roleValue, roleLengthValue, bodyLengthValue, digestLengthValue any
		if err := rows.Scan(&roleValue, &roleLengthValue, &bodyLengthValue, &digestLengthValue); err != nil {
			_ = rows.Close()
			return storageFailure(ctx, stage, err)
		}
		role, roleOK := roleValue.(string)
		roleLength, roleLengthOK := rawInt64(roleLengthValue)
		bodyLength, bodyLengthOK := rawInt64(bodyLengthValue)
		digestLength, digestLengthOK := rawInt64(digestLengthValue)
		if !roleOK || !roleLengthOK || roleLength <= 0 || roleLength > 16 || (role != "outcome" && role != "retirement" && role != "first-conflict") || !bodyLengthOK || bodyLength <= 0 || uint64(bodyLength) > s.attemptLimits.EvidenceSlotBytes || !digestLengthOK || digestLength != 32 || len(metadata) >= 3 {
			_ = rows.Close()
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
		metadata = append(metadata, attemptEvidenceMeta{role: role})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return storageFailure(ctx, stage, err)
	}
	if err := rows.Close(); err != nil {
		return storageFailure(ctx, stage, err)
	}
	roles := map[string][]byte{}
	wires := map[string]attemptEvidenceWire{}
	var firstConflictBody, firstConflictDigest []byte
	var total uint64
	for _, item := range metadata {
		var bodyValue, digestValue any
		if err := q.QueryRowContext(ctx, "SELECT body,digest FROM attempt_evidence WHERE attempt_id=? AND role=?", attempt.core.AttemptID, item.role).Scan(&bodyValue, &digestValue); err != nil {
			return storageFailure(ctx, stage, err)
		}
		body, bodyOK := rawBytes(bodyValue)
		digest, digestOK := rawBytes(digestValue)
		if !bodyOK || !digestOK || uint64(len(body)) > s.attemptLimits.EvidenceSlotBytes || len(digest) != 32 {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
		calculated := domainHash("systems.lamb.dottie.publication-attempt-evidence.v1", body)
		if !bytes.Equal(calculated[:], digest) {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
		roles[item.role] = bytes.Clone(body)
		if item.role == "first-conflict" {
			firstConflictBody = bytes.Clone(body)
			firstConflictDigest = bytes.Clone(digest)
		} else {
			var wire attemptEvidenceWire
			if strictJSON(body, &wire) != nil || wire.Version != 1 || s.validateAttemptEvidenceWire(attempt, item.role, wire) != nil {
				return classified(ErrSchema, stage, ReasonCorrupt)
			}
			wires[item.role] = wire
		}
		total += uint64(len(body) + len(digest))
	}
	if total > s.attemptLimits.EvidenceBytes {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	if outcome, exists := wires["outcome"]; exists {
		if AttemptOutcome(outcome.Outcome) != attempt.outcome {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
	}
	if terminalOutcome(attempt.outcome) {
		if _, exists := wires["outcome"]; !exists {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
	}
	var conflictEventBody any
	err = q.QueryRowContext(ctx, "SELECT body FROM attempt_events WHERE attempt_id=? AND kind='outcome-lost-fence'", attempt.core.AttemptID).Scan(&conflictEventBody)
	if errors.Is(err, sql.ErrNoRows) {
		if firstConflictBody != nil || attempt.outcome == OutcomeLostFence {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
	} else if err != nil {
		return storageFailure(ctx, stage, err)
	} else {
		if firstConflictBody == nil || attempt.outcome != OutcomeLostFence {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
		eventBody, ok := rawBytes(conflictEventBody)
		if !ok {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
		if _, err := s.validateFirstConflict(attempt, firstConflictBody, firstConflictDigest, eventBody); err != nil {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
	}
	if len(attempt.terminal) > 0 {
		found := false
		for _, body := range roles {
			if bytes.Equal(body, attempt.terminal) {
				found = true
			}
		}
		if !found {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
	}
	if len(attempt.retirement) > 0 && !bytes.Equal(roles["retirement"], attempt.retirement) {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	if attempt.lifecycle == AttemptRetiredAbandoned && len(attempt.retirement) == 0 {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	if attempt.lifecycle != AttemptRetiredAbandoned && len(attempt.retirement) != 0 {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	return nil
}

func (s *Store) validateAttemptPayloadReference(ctx context.Context, q queryer, attempt storedAttempt, stage Stage) error {
	var refCIDValue, objectCIDValue, sizeValue, basenameValue any
	if err := q.QueryRowContext(ctx, "SELECT attempt_payload_refs.blob_cid,payload_objects.blob_cid,payload_objects.size,payload_objects.basename FROM attempt_payload_refs JOIN payload_objects USING(blob_cid) WHERE attempt_payload_refs.attempt_id=?", attempt.core.AttemptID).Scan(&refCIDValue, &objectCIDValue, &sizeValue, &basenameValue); err != nil {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	refCID, refOK := rawBytes(refCIDValue)
	objectCID, objectOK := rawBytes(objectCIDValue)
	size, sizeOK := rawInt64(sizeValue)
	basename, nameOK := basenameValue.(string)
	wantedName, nameErr := payloadBasenameFromCID(attempt.core.BlobCID)
	if !refOK || !objectOK || !bytes.Equal(refCID, attempt.core.BlobCID) || !bytes.Equal(objectCID, attempt.core.BlobCID) || !sizeOK || size <= 0 || uint64(size) != attempt.core.BlobSize || !nameOK || !validPayloadBasename(basename) || nameErr != nil || wantedName != basename {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	return nil
}

func (s *Store) validateRetainedPublication(ctx context.Context, q queryer, attempt storedAttempt, stage Stage) error {
	var recordValue, blobValue, seqValue, sizeValue, revisionValue any
	var recordLengthValue, blobLengthValue any
	if err := q.QueryRowContext(ctx, "SELECT substr(record_cid,1,129),length(record_cid),substr(blob_cid,1,129),length(blob_cid),sequence,size,accepted_revision FROM retained_publications WHERE attempt_id=?", attempt.core.AttemptID).Scan(&recordValue, &recordLengthValue, &blobValue, &blobLengthValue, &seqValue, &sizeValue, &revisionValue); err != nil {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	record, recordOK := rawBytes(recordValue)
	recordLength, recordLengthOK := rawInt64(recordLengthValue)
	blob, blobOK := rawBytes(blobValue)
	blobLength, blobLengthOK := rawInt64(blobLengthValue)
	seq, seqOK := rawInt64(seqValue)
	size, sizeOK := rawInt64(sizeValue)
	revision, revisionOK := rawInt64(revisionValue)
	snapshot, err := publication.DecodeSnapshot(attempt.core.SnapshotRecord)
	if err != nil || !recordOK || !recordLengthOK || recordLength <= 0 || recordLength > publication.MaxCIDBytes || int64(len(record)) != recordLength || !blobOK || !blobLengthOK || blobLength <= 0 || blobLength > publication.MaxCIDBytes || int64(len(blob)) != blobLength || !bytes.Equal(record, attempt.core.SnapshotCID) || !bytes.Equal(blob, attempt.core.BlobCID) || !seqOK || seq < 0 || uint64(seq) != snapshot.PublicationSeq || !sizeOK || size <= 0 || uint64(size) != attempt.core.BlobSize || !revisionOK || revision <= 0 {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	var modeValue, floorValue, eventDigestValue any
	if err := q.QueryRowContext(ctx, "SELECT mode,new_floor,digest FROM accepted_events WHERE revision=?", revision).Scan(&modeValue, &floorValue, &eventDigestValue); err != nil {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	mode, modeOK := modeValue.(string)
	floorBytes, floorOK := rawBytes(floorValue)
	digest, digestOK := rawBytes(eventDigestValue)
	acceptedFloor, floorErr := decodeFloor(floorBytes)
	if !modeOK || (mode != string(ModeFirstUse) && mode != string(ModeAdvance)) || !floorOK || !digestOK || len(digest) != 32 || floorErr != nil || acceptedFloor.Revision != uint64(revision) || !bytes.Equal(acceptedFloor.RecordCID, attempt.core.SnapshotCID) || !bytes.Equal(acceptedFloor.BlobCID, attempt.core.BlobCID) || acceptedFloor.Sequence != snapshot.PublicationSeq || !bytes.Equal(acceptedFloor.AcceptedEventDigest[:], digest) || !sameBinding(acceptedFloor.Binding, s.binding) {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	var acceptedRecord any
	if err := q.QueryRowContext(ctx, "SELECT raw FROM accepted_records WHERE cid=?", attempt.core.SnapshotCID).Scan(&acceptedRecord); err != nil {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	raw, rawOK := rawBytes(acceptedRecord)
	if !rawOK || !bytes.Equal(raw, attempt.core.SnapshotRecord) {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	return nil
}

func (s *Store) reconcileAttemptMutationRevision(ctx context.Context, q queryer, stage Stage) (uint64, error) {
	value, err := readValueBounded(ctx, q, "attempt_mutation_revision", 8)
	if err != nil || len(value) != 8 {
		return 0, classified(ErrSchema, stage, ReasonCorrupt)
	}
	revision := binary.BigEndian.Uint64(value)
	if revision > math.MaxInt64 {
		return 0, classified(ErrSchema, stage, ReasonCorrupt)
	}
	return revision, nil
}
