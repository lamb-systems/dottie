package publicationstate

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"math"

	"github.com/lamb-systems/dottie/internal/publication"
)

type FirstConflictEvidence struct {
	AttemptID    [16]byte
	ID           [32]byte
	Evidence     []byte
	Head         []byte
	HeadKey      string
	HeadRecord   []byte
	HeadSequence uint64
}

type firstConflictRecord struct {
	Body   []byte
	ID     [32]byte
	Digest []byte
}

func makeFirstConflictRecord(attempt storedAttempt, proofBytes []byte, ordinal uint32, mutationRevision uint64, stateDigest [32]byte, blocked string) (firstConflictRecord, error) {
	var proof attemptEvidenceWire
	if len(proofBytes) == 0 || strictJSON(proofBytes, &proof) != nil || proof.Version != 1 || proof.Role != "outcome" || proof.Outcome != string(OutcomeLostFence) || ordinal == 0 || mutationRevision == 0 || len(stateDigest) != 32 || (blocked != "" && blocked != "blocked-floor-replaced") {
		return firstConflictRecord{}, errors.New("first conflict")
	}
	coreDigest := makeAttemptCoreDigest(attempt.coreBytes)
	wire := firstConflictWire{Version: 1, AttemptID: bytes.Clone(attempt.core.AttemptID), CoreDigest: bytes.Clone(coreDigest[:]), EventOrdinal: ordinal, MutationRevision: mutationRevision, EventStateDigest: bytes.Clone(stateDigest[:]), Blocked: blocked, Proof: proof}
	body, err := canonicalJSON(wire)
	if err != nil {
		return firstConflictRecord{}, err
	}
	id := domainHash("systems.lamb.dottie.publication-attempt-first-conflict.v1", body)
	digest := domainHash("systems.lamb.dottie.publication-attempt-evidence.v1", body)
	return firstConflictRecord{Body: body, ID: id, Digest: bytes.Clone(digest[:])}, nil
}

func (s *Store) validateFirstConflict(attempt storedAttempt, body, digest, eventBody []byte) (FirstConflictEvidence, error) {
	var wire firstConflictWire
	if len(body) == 0 || len(body) > int(s.attemptLimits.EvidenceSlotBytes) || strictJSON(body, &wire) != nil || wire.Version != 1 {
		return FirstConflictEvidence{}, errors.New("first conflict envelope")
	}
	canonical, err := canonicalJSON(wire)
	if err != nil || !bytes.Equal(canonical, body) {
		return FirstConflictEvidence{}, errors.New("first conflict canonical")
	}
	id := domainHash("systems.lamb.dottie.publication-attempt-first-conflict.v1", body)
	rowDigest := domainHash("systems.lamb.dottie.publication-attempt-evidence.v1", body)
	coreDigest := makeAttemptCoreDigest(attempt.coreBytes)
	if len(digest) != 32 || !bytes.Equal(rowDigest[:], digest) || len(wire.AttemptID) != 16 || !bytes.Equal(wire.AttemptID, attempt.core.AttemptID) || len(wire.CoreDigest) != 32 || !bytes.Equal(wire.CoreDigest, coreDigest[:]) || wire.EventOrdinal == 0 || wire.MutationRevision <= attempt.createdOrder || wire.MutationRevision > attempt.mutationRevision || wire.MutationRevision > math.MaxInt64 || len(wire.EventStateDigest) != 32 || (wire.Blocked != "" && wire.Blocked != "blocked-floor-replaced") || attempt.outcome != OutcomeLostFence {
		return FirstConflictEvidence{}, errors.New("first conflict binding")
	}
	var event attemptEventWire
	if strictJSON(eventBody, &event) != nil || event.Version != 1 || event.Kind != "outcome-lost-fence" || event.Ordinal != wire.EventOrdinal || len(event.Evidence) != 32 || !bytes.Equal(event.Evidence, id[:]) || !bytes.Equal(event.StateDigest, wire.EventStateDigest) {
		return FirstConflictEvidence{}, errors.New("first conflict event")
	}
	proofBytes, err := encodeAttemptEvidence(wire.Proof)
	if err != nil || wire.Proof.Version != 1 || wire.Proof.Role != "outcome" || wire.Proof.Outcome != string(OutcomeLostFence) || s.validateAttemptEvidenceWire(attempt, "outcome", wire.Proof) != nil {
		return FirstConflictEvidence{}, errors.New("first conflict proof")
	}
	expectedStateDigest, err := makeAttemptStateDigest(attempt.coreBytes, AttemptMayHaveSubmitted, OutcomeLostFence, wire.Blocked, wire.MutationRevision, proofBytes, nil)
	if err != nil || !bytes.Equal(expectedStateDigest[:], wire.EventStateDigest) {
		return FirstConflictEvidence{}, errors.New("first conflict state")
	}
	if len(wire.Proof.Suffix) == 0 {
		return FirstConflictEvidence{}, errors.New("first conflict suffix")
	}
	last := wire.Proof.Suffix[len(wire.Proof.Suffix)-1]
	record, err := publication.DecodeSnapshot(last.Raw)
	if err != nil {
		return FirstConflictEvidence{}, errors.New("first conflict head record")
	}
	return FirstConflictEvidence{AttemptID: attemptIDFromCore(attempt.core), ID: id, Evidence: bytes.Clone(body), Head: bytes.Clone(wire.Proof.Head), HeadKey: last.Key, HeadRecord: bytes.Clone(last.Raw), HeadSequence: record.PublicationSeq}, nil
}

func attemptIDFromCore(core attemptCoreWire) [16]byte {
	var id [16]byte
	copy(id[:], core.AttemptID)
	return id
}

func (s *Store) ReadFirstConflict(ctx context.Context, id [16]byte) (FirstConflictEvidence, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkContext(ctx, StageHistory); err != nil {
		return FirstConflictEvidence{}, false, err
	}
	if err := s.requireReadback(StageHistory); err != nil {
		return FirstConflictEvidence{}, false, err
	}
	if _, err := s.readState(ctx, s.conn, StageHistory); err != nil {
		return FirstConflictEvidence{}, false, err
	}
	attempt, err := s.loadStoredAttempt(ctx, s.conn, id, StageHistory)
	if err != nil {
		return FirstConflictEvidence{}, false, err
	}
	var bodyValue any
	err = s.conn.QueryRowContext(ctx, "SELECT body FROM attempt_evidence WHERE attempt_id=? AND role='first-conflict'", id[:]).Scan(&bodyValue)
	if errors.Is(err, sql.ErrNoRows) {
		return FirstConflictEvidence{}, false, nil
	}
	if err != nil {
		return FirstConflictEvidence{}, false, storageFailure(ctx, StageHistory, err)
	}
	body, ok := rawBytes(bodyValue)
	if !ok {
		return FirstConflictEvidence{}, false, classified(ErrSchema, StageHistory, ReasonCorrupt)
	}
	var digestValue, eventValue any
	if err := s.conn.QueryRowContext(ctx, "SELECT digest FROM attempt_evidence WHERE attempt_id=? AND role='first-conflict'", id[:]).Scan(&digestValue); err != nil {
		return FirstConflictEvidence{}, false, storageFailure(ctx, StageHistory, err)
	}
	if err := s.conn.QueryRowContext(ctx, "SELECT body FROM attempt_events WHERE attempt_id=? AND kind='outcome-lost-fence'", id[:]).Scan(&eventValue); err != nil {
		return FirstConflictEvidence{}, false, classified(ErrSchema, StageHistory, ReasonCorrupt)
	}
	digest, digestOK := rawBytes(digestValue)
	eventBody, eventOK := rawBytes(eventValue)
	if !digestOK || !eventOK {
		return FirstConflictEvidence{}, false, classified(ErrSchema, StageHistory, ReasonCorrupt)
	}
	result, err := s.validateFirstConflict(attempt, body, digest, eventBody)
	if err != nil {
		return FirstConflictEvidence{}, false, classified(ErrSchema, StageHistory, ReasonCorrupt)
	}
	return result, true, nil
}
