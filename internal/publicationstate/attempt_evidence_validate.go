package publicationstate

import (
	"bytes"
	"errors"

	"github.com/lamb-systems/dottie/internal/publication"
)

func (s *Store) validateAttemptEvidenceWire(attempt storedAttempt, databaseRole string, wire attemptEvidenceWire) error {
	if wire.AttemptedKey != attempt.core.SnapshotKey || !validAttemptEvidenceRole(databaseRole, wire.Role) {
		return errors.New("evidence role")
	}
	if wire.Role == "retirement" && len(wire.ViewDigest) == 0 {
		if !bytes.Equal(wire.AttemptedRecord, attempt.core.SnapshotRecord) || len(wire.Suffix) != 0 {
			return errors.New("retirement evidence")
		}
		return nil
	}
	if len(wire.ViewDigest) != 32 {
		return errors.New("view digest")
	}
	origin, err := bindingFromWire(wire.Origin)
	expectedScope := ViewScopeWholeRepository
	if s.binding.Backend == BackendSpaces {
		expectedScope = ViewScopeDedicatedSpace
	}
	if err != nil || !sameBinding(origin, s.binding) || wire.Scope != string(expectedScope) {
		return errors.New("evidence origin")
	}
	context, err := contextFromWire(wire.Context)
	if err != nil || validateContext(context, s.binding, s.limits) != nil {
		return errors.New("evidence context")
	}
	if wire.Outcome != string(OutcomeNotSubmitted) {
		if err := s.validateAttemptPolicy(attempt.core, context, StageResolve); err != nil {
			return errors.New("evidence policy")
		}
	}
	if wire.Role == "submission" {
		if !bytes.Equal(wire.AttemptedRecord, attempt.core.SnapshotRecord) || !bytes.Equal(wire.PredecessorRecord, attempt.core.PredecessorRecord) || wire.Outcome != string(OutcomeUnresolved) || len(wire.Suffix) != 0 {
			return errors.New("submission evidence")
		}
		if attempt.core.Kind == string(AttemptGenesis) {
			if len(wire.Head) != 0 {
				return errors.New("genesis submission head")
			}
			return nil
		}
		if attempt.core.CapturedFloor == nil {
			return errors.New("successor submission floor")
		}
		floor, err := floorFromWire(*attempt.core.CapturedFloor)
		if err != nil || !bytes.Equal(wire.Head, floor.Head) || publication.VerifyHeadBinding(wire.Head, attempt.core.PredecessorRecord, attempt.core.PredecessorKey) != nil {
			return errors.New("successor submission head")
		}
		return nil
	}
	outcome := AttemptOutcome(wire.Outcome)
	if !validOutcome(outcome) {
		return errors.New("outcome evidence")
	}
	if attempt.core.Kind == string(AttemptSuccessor) && !bytes.Equal(wire.PredecessorRecord, attempt.core.PredecessorRecord) {
		return errors.New("evidence predecessor")
	}
	if attempt.core.Kind == string(AttemptGenesis) && len(wire.PredecessorRecord) != 0 {
		return errors.New("genesis evidence predecessor")
	}
	switch outcome {
	case OutcomeAbsentUnresolved:
		if len(wire.AttemptedRecord) != 0 || len(wire.Suffix) != 0 {
			return errors.New("absent evidence")
		}
		if len(wire.Head) == 0 {
			if attempt.core.Kind == string(AttemptGenesis) {
				return nil
			}
			return errors.New("missing successor head")
		}
		head, err := publication.DecodeHead(wire.Head)
		candidate, candidateErr := publication.DecodeSnapshot(attempt.core.SnapshotRecord)
		if err != nil || candidateErr != nil || head.PublicationSeq >= candidate.PublicationSeq {
			return errors.New("absent evidence sequence")
		}
		if attempt.core.Kind == string(AttemptSuccessor) {
			floor, err := floorFromWire(*attempt.core.CapturedFloor)
			if err != nil || head.PublicationSeq != floor.Sequence || !bytes.Equal(head.SnapshotCID, floor.RecordCID) || !bytes.Equal(wire.Head, floor.Head) || publication.VerifyHeadBinding(wire.Head, attempt.core.PredecessorRecord, attempt.core.PredecessorKey) != nil {
				return errors.New("absent evidence predecessor")
			}
		} else {
			return errors.New("genesis absent view has head")
		}
	case OutcomeCurrent:
		if !bytes.Equal(wire.AttemptedRecord, attempt.core.SnapshotRecord) || len(wire.Suffix) != 1 || !bytes.Equal(wire.AttemptedRecord, wire.Suffix[0].Raw) {
			return errors.New("current evidence")
		}
		if err := s.validateEvidenceHeadAndSuffix(attempt, wire, false); err != nil {
			return err
		}
		head, err := publication.DecodeHead(wire.Head)
		if err != nil || head.PublicationSeq != attemptSequence(attempt) || !bytes.Equal(head.SnapshotCID, attempt.core.SnapshotCID) {
			return errors.New("current head")
		}
	case OutcomeSuperseded:
		if !bytes.Equal(wire.AttemptedRecord, attempt.core.SnapshotRecord) || len(wire.Suffix) < 2 || !bytes.Equal(wire.AttemptedRecord, wire.Suffix[0].Raw) {
			return errors.New("superseded evidence")
		}
		if err := s.validateEvidenceHeadAndSuffix(attempt, wire, false); err != nil {
			return err
		}
		head, err := publication.DecodeHead(wire.Head)
		if err != nil || head.PublicationSeq <= attemptSequence(attempt) {
			return errors.New("superseded head")
		}
	case OutcomeLostFence:
		if len(wire.Suffix) == 0 || bytes.Equal(wire.AttemptedRecord, attempt.core.SnapshotRecord) || !bytes.Equal(wire.AttemptedRecord, wire.Suffix[0].Raw) {
			return errors.New("lost fence evidence")
		}
		if err := s.validateEvidenceHeadAndSuffix(attempt, wire, attempt.core.Kind == string(AttemptSuccessor)); err != nil {
			return err
		}
		occupant, err := publication.DecodeSnapshot(wire.Suffix[0].Raw)
		if err != nil || occupant.PublicationSeq != attemptSequence(attempt) {
			return errors.New("lost fence occupant")
		}
		if attempt.core.Kind == string(AttemptSuccessor) {
			if err := publication.VerifySuccessor(attempt.core.PredecessorRecord, wire.Suffix[0].Raw, wire.Suffix[0].Key); err != nil {
				return errors.New("lost fence predecessor")
			}
		}
	case OutcomeNotSubmitted:
		if len(wire.AttemptedRecord) > 0 {
			if _, err := publication.DecodeSnapshot(wire.AttemptedRecord); err != nil || len(wire.Suffix) == 0 || !bytes.Equal(wire.AttemptedRecord, wire.Suffix[0].Raw) {
				return errors.New("never submitted evidence")
			}
			if err := s.validateEvidenceHeadAndSuffix(attempt, wire, false); err != nil {
				return err
			}
		} else if len(wire.Suffix) != 0 {
			return errors.New("never submitted evidence suffix")
		}
	}
	return nil
}

func validAttemptEvidenceRole(databaseRole, wireRole string) bool {
	switch databaseRole {
	case "submission":
		return wireRole == "submission"
	case "outcome":
		return wireRole == "outcome"
	case "retirement":
		return wireRole == "retirement" || wireRole == "outcome"
	default:
		return false
	}
}

func (s *Store) validateEvidenceHeadAndSuffix(attempt storedAttempt, wire attemptEvidenceWire, predecessorLink bool) error {
	if len(wire.Head) == 0 || len(wire.Suffix) == 0 {
		return errors.New("evidence chain")
	}
	links := uint64(len(wire.Suffix) - 1)
	if predecessorLink {
		links++
	}
	if links > uint64(s.limits.MaxLineageLinks) {
		return errors.New("evidence lineage limit")
	}
	var previousRaw []byte
	var previousCID []byte
	var lastRecord publication.SnapshotRecord
	for index, block := range wire.Suffix {
		sequence, err := publication.ParseSequenceKey(block.Key)
		if err != nil {
			return errors.New("evidence key")
		}
		record, err := publication.DecodeSnapshot(block.Raw)
		if err != nil || record.PublicationSeq != sequence {
			return errors.New("evidence record")
		}
		cid, err := publication.RecordCID(block.Raw)
		if err != nil {
			return errors.New("evidence cid")
		}
		if index == 0 {
			if sequence != attemptSequence(attempt) {
				return errors.New("evidence first sequence")
			}
		} else {
			if err := publication.VerifySuccessor(previousRaw, block.Raw, block.Key); err != nil {
				return errors.New("evidence successor")
			}
		}
		previousRaw = block.Raw
		previousCID = cid
		lastRecord = record
	}
	head, err := publication.DecodeHead(wire.Head)
	if err != nil || head.PublicationSeq != lastRecord.PublicationSeq || !bytes.Equal(head.SnapshotCID, previousCID) || !bytes.Equal(head.BlobCID, lastRecord.Blob.CID) || publication.VerifyHeadBinding(wire.Head, previousRaw, wire.Suffix[len(wire.Suffix)-1].Key) != nil {
		return errors.New("evidence head")
	}
	return nil
}

func attemptSequence(attempt storedAttempt) uint64 {
	record, err := publication.DecodeSnapshot(attempt.core.SnapshotRecord)
	if err != nil {
		return 0
	}
	return record.PublicationSeq
}
