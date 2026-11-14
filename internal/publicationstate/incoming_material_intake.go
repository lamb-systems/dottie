package publicationstate

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"

	"golang.org/x/sys/unix"

	"github.com/lamb-systems/dottie/internal/publication"
)

const stageAcceptMaterial Stage = "accept_material"

type materialAttachment struct {
	payload []byte
	blob    publication.BlobReference
	name    string
}

func (s *Store) acceptMaterial(ctx context.Context, mode Mode, expectedStateToken [32]byte, observation Observation, payload []byte, confirmation [32]byte) (Floor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkContext(ctx, stageAcceptMaterial); err != nil {
		return zeroFloor(), err
	}
	if err := s.requireReadback(stageAcceptMaterial); err != nil {
		return zeroFloor(), err
	}
	if s.schemaVersion != 3 {
		return zeroFloor(), classified(ErrSchema, stageAcceptMaterial, ReasonUpgradeRequired)
	}
	if !validMode(mode) {
		return zeroFloor(), classified(ErrInvalid, StageInput, ReasonMode)
	}
	validated, err := validateObservation(observation, s.binding, s.limits)
	if err != nil {
		return zeroFloor(), err
	}
	blob := blobReference(validated.candidate.raw)
	if _, err := publication.DecodePayload(payload, blob); err != nil {
		return zeroFloor(), err
	}
	material := materialAttachment{payload: payload, blob: blob, name: payloadBasename(payload)}
	if validatePayloadForCustody(material.payload, material.blob, material.name) != nil {
		return zeroFloor(), classified(ErrInvalid, stageAcceptMaterial, ReasonRecordSet)
	}
	if err := s.preflightSidecars(); err != nil {
		return zeroFloor(), storageFailure(ctx, stageAcceptMaterial, err)
	}
	var accepted Floor
	var attemptMutationChanged bool
	err = s.withTx(ctx, stageAcceptMaterial, func(tx *sql.Tx) error {
		floor, changed, txErr := s.acceptTx(ctx, tx, stageAcceptMaterial, mode, expectedStateToken, validated, confirmation, &material)
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

func (s *Store) acceptTx(ctx context.Context, tx *sql.Tx, stage Stage, mode Mode, expectedStateToken [32]byte, validated validatedObservation, confirmation [32]byte, material *materialAttachment) (Floor, bool, error) {
	var accepted Floor
	var attemptMutationChanged bool
	state, err := s.readState(ctx, tx, stage)
	if err != nil {
		return zeroFloor(), false, err
	}
	if !bytes.Equal(expectedStateToken[:], state.token[:]) {
		return zeroFloor(), false, classified(ErrConsent, stage, ReasonStale)
	}
	trace, err := s.resolveTrace(ctx, tx, validated, state.floor, stage)
	if err != nil {
		return zeroFloor(), false, err
	}
	proposal, err := s.proposal(mode, validated, state, trace, stage)
	if err != nil {
		return zeroFloor(), false, err
	}
	samePosition := false
	if mode == ModeAdvance && trace.reason == "" {
		if !allZero(confirmation[:]) {
			return zeroFloor(), false, classified(ErrConsent, stage, ReasonMode)
		}
		samePosition = trace.stop == "same"
	}
	if mode == ModeAdvance && trace.stop == "joined" && !allZero(confirmation[:]) {
		return zeroFloor(), false, classified(ErrConsent, stage, ReasonMode)
	}
	if mode != ModeAdvance && (allZero(confirmation[:]) || !bytes.Equal(confirmation[:], proposal.Confirmation[:])) {
		return zeroFloor(), false, classified(ErrConsent, stage, ReasonConfirmation)
	}
	if samePosition {
		accepted = cloneFloor(*state.floor)
	} else {
		if err := s.rejectActiveCandidate(ctx, tx, validated.candidate, stage); err != nil {
			return zeroFloor(), false, err
		}
		if mode == ModeReplaceFloor {
			changed, err := s.blockActiveAttemptTx(ctx, tx, stage)
			if err != nil {
				return zeroFloor(), false, err
			}
			attemptMutationChanged = changed
		}
		result, err := s.acceptFloorTx(ctx, tx, mode, state, validated, trace, stage, nil)
		if err != nil {
			return zeroFloor(), false, err
		}
		accepted = result
	}
	if material != nil {
		ownerName, ownerRecord, ownerBlob, ownerErr := s.acceptedMaterialOwner(ctx, tx, accepted, stage)
		if ownerErr == nil {
			if !materialOwnerMatches(ownerName, ownerRecord, ownerBlob, validated.candidate.raw, *material) {
				return zeroFloor(), false, classified(ErrSchema, stage, ReasonCorrupt)
			}
			if err := s.openPayloadDirectoryForRead(); err != nil {
				return zeroFloor(), false, classifyAcceptedMaterialDirectory(err, stage)
			}
			if _, err := s.inspectPayloadFile(ownerName, nil, ownerBlob); err != nil {
				return zeroFloor(), false, classifyMaterialCustody(err)
			}
		} else if materialNotRetained(ownerErr) {
			if err := s.attachIncomingMaterialTx(ctx, tx, accepted, *material); err != nil {
				return zeroFloor(), false, err
			}
		} else {
			return zeroFloor(), false, ownerErr
		}
		fresh, err := s.readState(ctx, tx, stage)
		if err != nil {
			return zeroFloor(), false, err
		}
		if fresh.floor == nil || !sameAcceptedFloor(*fresh.floor, accepted) {
			return zeroFloor(), false, classified(ErrSchema, stage, ReasonCorrupt)
		}
		readbackName, readbackRecord, readbackBlob, readbackErr := s.acceptedMaterialOwner(ctx, tx, accepted, stage)
		if readbackErr != nil {
			return zeroFloor(), false, readbackErr
		}
		if !materialOwnerMatches(readbackName, readbackRecord, readbackBlob, validated.candidate.raw, *material) {
			return zeroFloor(), false, classified(ErrSchema, stage, ReasonCorrupt)
		}
	}
	return accepted, attemptMutationChanged, nil
}

func (s *Store) attachIncomingMaterialTx(ctx context.Context, tx *sql.Tx, floor Floor, material materialAttachment) error {
	if err := s.checkPayloadCapacityWithQueryer(ctx, tx, material.name, material.blob.Size, true); err != nil {
		return classified(ErrLimit, stageAcceptMaterial, ReasonCapacity)
	}
	if _, _, err := s.persistPayload(ctx, tx, material.payload, material.blob, material.name); err != nil {
		return classifyMaterialCustody(err)
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO payload_objects(blob_cid,size,basename,logical_bytes) VALUES(?,?,?,?) ON CONFLICT(blob_cid) DO NOTHING", material.blob.CID, int64(material.blob.Size), material.name, int64(material.blob.Size)); err != nil {
		return classified(ErrStorage, stageAcceptMaterial, ReasonIO)
	}
	var cataloguedName string
	var cataloguedSize any
	if err := tx.QueryRowContext(ctx, "SELECT basename,size FROM payload_objects WHERE blob_cid=?", material.blob.CID).Scan(&cataloguedName, &cataloguedSize); err != nil {
		return storageFailure(ctx, stageAcceptMaterial, err)
	}
	size, ok := rawInt64(cataloguedSize)
	if !ok || size <= 0 || uint64(size) != material.blob.Size || cataloguedName != material.name {
		return classified(ErrSchema, stageAcceptMaterial, ReasonCorrupt)
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO accepted_material_refs(accepted_revision,record_cid,blob_cid) VALUES(?,?,?)", int64(floor.Revision), floor.RecordCID, floor.BlobCID); err != nil {
		return classified(ErrStorage, stageAcceptMaterial, ReasonIO)
	}
	return nil
}

func materialOwnerMatches(name string, record []byte, blob publication.BlobReference, expectedRecord []byte, material materialAttachment) bool {
	return name == material.name && bytes.Equal(record, expectedRecord) && bytes.Equal(blob.CID, material.blob.CID) && blob.Size == material.blob.Size
}

func materialNotRetained(err error) bool {
	var stateError *Error
	return errors.As(err, &stateError) && stateError.Class() == ErrStorage && stateError.Reason() == ReasonMaterialNotRetained
}

func classifyMaterialCustody(err error) error {
	if errors.Is(err, unix.ENOENT) {
		return classified(ErrStorage, stageAcceptMaterial, ReasonMaterialMissing)
	}
	if errors.Is(err, errUnsafePayloadObject) || errors.Is(err, unix.ELOOP) {
		return classified(ErrStorage, stageAcceptMaterial, ReasonMaterialUnsafe)
	}
	if errors.Is(err, errCorruptPayloadObject) || errors.Is(err, io.ErrUnexpectedEOF) {
		return classified(ErrStorage, stageAcceptMaterial, ReasonMaterialCorrupt)
	}
	return classified(ErrStorage, stageAcceptMaterial, ReasonIO)
}
