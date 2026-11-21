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

const StageAcceptMaterial Stage = "accept_material"

type materialEntry struct {
	content []byte
	blob    publication.BlobReference
}

type materialAttachment struct {
	form     PayloadForm
	payload  []byte
	blob     publication.BlobReference
	name     string
	manifest *ManifestPayload
	entries  []materialEntry
}

func (s *Store) AcceptMaterial(
	ctx context.Context,
	mode Mode,
	expectedStateToken [32]byte,
	observation Observation,
	payload []byte,
	confirmation [32]byte,
) (Floor, error) {
	return s.AcceptMaterialInput(
		ctx,
		mode,
		expectedStateToken,
		observation,
		MaterialInput{Payload: payload},
		confirmation,
	)
}

func (s *Store) AcceptMaterialInput(
	ctx context.Context,
	mode Mode,
	expectedStateToken [32]byte,
	observation Observation,
	input MaterialInput,
	confirmation [32]byte,
) (Floor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkContext(ctx, StageAcceptMaterial); err != nil {
		return zeroFloor(), err
	}
	if err := s.requireReadback(StageAcceptMaterial); err != nil {
		return zeroFloor(), err
	}
	if s.schemaVersion != 3 {
		return zeroFloor(), classified(ErrSchema, StageAcceptMaterial, ReasonUpgradeRequired)
	}
	if !validMode(mode) {
		return zeroFloor(), classified(ErrInvalid, StageInput, ReasonMode)
	}
	validated, err := validateMaterialObservation(observation, s.binding, s.limits)
	if err != nil {
		return zeroFloor(), err
	}
	material, err := validateMaterialInput(input, validated, s.attemptLimits)
	if err != nil {
		return zeroFloor(), err
	}
	if material.form == PayloadFormPacked && validatePayloadForCustody(material.payload, material.blob, material.name) != nil {
		return zeroFloor(), classified(ErrInvalid, StageAcceptMaterial, ReasonRecordSet)
	}
	if err := s.preflightSidecars(); err != nil {
		return zeroFloor(), storageFailure(ctx, StageAcceptMaterial, err)
	}
	var accepted Floor
	var attemptMutationChanged bool
	err = s.withTx(ctx, StageAcceptMaterial, func(tx *sql.Tx) error {
		floor, changed, txErr := s.acceptTx(
			ctx,
			tx,
			StageAcceptMaterial,
			mode,
			expectedStateToken,
			validated,
			confirmation,
			&material,
		)
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

func (s *Store) acceptTx(
	ctx context.Context,
	tx *sql.Tx,
	stage Stage,
	mode Mode,
	expectedStateToken [32]byte,
	validated validatedObservation,
	confirmation [32]byte,
	material *materialAttachment,
) (Floor, bool, error) {
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
		owner, ownerErr := s.acceptedMaterialOwner(ctx, tx, accepted, stage)
		if ownerErr == nil {
			if err := s.verifyOwnedMaterial(ctx, owner, validated.candidate.raw, *material, stage); err != nil {
				return zeroFloor(), false, err
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
		readback, readbackErr := s.acceptedMaterialOwner(ctx, tx, accepted, stage)
		if readbackErr != nil {
			return zeroFloor(), false, readbackErr
		}
		if err := s.verifyOwnedMaterial(ctx, readback, validated.candidate.raw, *material, stage); err != nil {
			return zeroFloor(), false, err
		}
	}
	return accepted, attemptMutationChanged, nil
}

func (s *Store) verifyOwnedMaterial(
	ctx context.Context,
	owner materialOwnership,
	expectedRecord []byte,
	material materialAttachment,
	stage Stage,
) error {
	if owner.form != material.form || !bytes.Equal(owner.record, expectedRecord) {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	if owner.form == PayloadFormManifest {
		if !sameManifestPayload(owner.manifest, material.manifest) {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
	} else if owner.name != material.name || !bytes.Equal(owner.blob.CID, material.blob.CID) ||
		owner.blob.Size != material.blob.Size {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	if err := s.openPayloadDirectoryForRead(); err != nil {
		return classifyAcceptedMaterialDirectory(err, stage)
	}
	if owner.form == PayloadFormManifest {
		return s.verifyManifestMaterialCustody(ctx, material)
	}
	if _, err := s.inspectPayloadFile(owner.name, nil, owner.blob); err != nil {
		return classifyMaterialCustody(err)
	}
	return nil
}

func (s *Store) verifyManifestMaterialCustody(ctx context.Context, material materialAttachment) error {
	seen := make(map[string]bool, len(material.entries))
	for _, entry := range material.entries {
		key := string(entry.blob.CID)
		if seen[key] {
			continue
		}
		seen[key] = true
		if err := s.checkContext(ctx, StageAcceptMaterial); err != nil {
			return err
		}
		name, err := payloadBasenameFromCID(entry.blob.CID)
		if err != nil || !validPayloadBasename(name) {
			return classified(ErrSchema, StageAcceptMaterial, ReasonCorrupt)
		}
		if _, err := s.inspectCustodyObject(name, nil, entry.blob, PayloadFormManifest); err != nil {
			return classifyMaterialCustody(err)
		}
	}
	return nil
}

func (s *Store) attachIncomingMaterialTx(
	ctx context.Context,
	tx *sql.Tx,
	floor Floor,
	material materialAttachment,
) error {
	if material.form == PayloadFormManifest {
		return s.attachIncomingManifestTx(ctx, tx, floor, material)
	}
	if err := s.checkPayloadCapacityWithQueryer(ctx, tx, material.name, material.blob.Size, true); err != nil {
		return classified(ErrLimit, StageAcceptMaterial, ReasonCapacity)
	}
	if _, _, err := s.persistPayload(ctx, tx, material.payload, material.blob, material.name); err != nil {
		return classifyMaterialCustody(err)
	}
	if _, err := tx.ExecContext(
		ctx,
		"INSERT INTO payload_objects(blob_cid,size,basename,logical_bytes) VALUES(?,?,?,?) ON CONFLICT(blob_cid) DO NOTHING",
		material.blob.CID,
		int64(material.blob.Size),
		material.name,
		int64(material.blob.Size),
	); err != nil {
		return classified(ErrStorage, StageAcceptMaterial, ReasonIO)
	}
	if err := requireCataloguedPayloadObject(ctx, tx, material.blob, material.name); err != nil {
		return err
	}
	if _, err := tx.ExecContext(
		ctx,
		"INSERT INTO accepted_material_refs(accepted_revision,record_cid,form,blob_cid,manifest) VALUES(?,?,'packed',?,NULL)",
		int64(floor.Revision),
		floor.RecordCID,
		floor.BlobCID,
	); err != nil {
		return classified(ErrStorage, StageAcceptMaterial, ReasonIO)
	}
	return nil
}

func (s *Store) attachIncomingManifestTx(
	ctx context.Context,
	tx *sql.Tx,
	floor Floor,
	material materialAttachment,
) error {
	if err := s.checkIncomingManifestCapacity(ctx, tx, material); err != nil {
		return err
	}
	seen := make(map[string]bool, len(material.entries))
	for _, entry := range material.entries {
		key := string(entry.blob.CID)
		if seen[key] {
			continue
		}
		seen[key] = true
		name := payloadBasename(entry.content)
		if _, _, err := s.persistPayloadObject(ctx, tx, entry.content, entry.blob, name, PayloadFormManifest); err != nil {
			return classifyMaterialCustody(err)
		}
		if _, err := tx.ExecContext(
			ctx,
			"INSERT INTO payload_objects(blob_cid,size,basename,logical_bytes) VALUES(?,?,?,?) ON CONFLICT(blob_cid) DO NOTHING",
			entry.blob.CID,
			int64(entry.blob.Size),
			name,
			int64(entry.blob.Size),
		); err != nil {
			return classified(ErrStorage, StageAcceptMaterial, ReasonIO)
		}
		if err := requireCataloguedPayloadObject(ctx, tx, entry.blob, name); err != nil {
			return err
		}
	}
	manifest, err := encodeRetainedManifest(material.manifest)
	if err != nil {
		return classified(ErrSchema, StageAcceptMaterial, ReasonCorrupt)
	}
	if _, err := tx.ExecContext(
		ctx,
		"INSERT INTO accepted_material_refs(accepted_revision,record_cid,form,blob_cid,manifest) VALUES(?,?,'manifest',NULL,?)",
		int64(floor.Revision),
		floor.RecordCID,
		manifest,
	); err != nil {
		return classified(ErrStorage, StageAcceptMaterial, ReasonIO)
	}
	return nil
}

func (s *Store) checkIncomingManifestCapacity(ctx context.Context, q queryer, material materialAttachment) error {
	objects := make(map[string]uint64, len(material.entries))
	for _, entry := range material.entries {
		name := payloadBasename(entry.content)
		if existing, present := objects[name]; present && existing != entry.blob.Size {
			return classified(ErrInvalid, StageAcceptMaterial, ReasonRecordSet)
		}
		objects[name] = entry.blob.Size
	}
	if err := s.checkPayloadBatchCapacity(ctx, q, objects, true); err != nil {
		return classified(ErrLimit, StageAcceptMaterial, ReasonCapacity)
	}
	return nil
}

func requireCataloguedPayloadObject(
	ctx context.Context,
	q queryer,
	blob publication.BlobReference,
	name string,
) error {
	var cataloguedName string
	var cataloguedSize any
	if err := q.QueryRowContext(ctx, "SELECT basename,size FROM payload_objects WHERE blob_cid=?", blob.CID).
		Scan(&cataloguedName, &cataloguedSize); err != nil {
		return storageFailure(ctx, StageAcceptMaterial, err)
	}
	size, ok := rawInt64(cataloguedSize)
	if !ok || size <= 0 || uint64(size) != blob.Size || cataloguedName != name {
		return classified(ErrSchema, StageAcceptMaterial, ReasonCorrupt)
	}
	return nil
}

func materialNotRetained(err error) bool {
	var stateError *Error
	return errors.As(err, &stateError) && stateError.Class() == ErrStorage &&
		stateError.Reason() == ReasonMaterialNotRetained
}

func classifyMaterialCustody(err error) error {
	if errors.Is(err, unix.ENOENT) {
		return classified(ErrStorage, StageAcceptMaterial, ReasonMaterialMissing)
	}
	if errors.Is(err, errUnsafePayloadObject) || errors.Is(err, unix.ELOOP) {
		return classified(ErrStorage, StageAcceptMaterial, ReasonMaterialUnsafe)
	}
	if errors.Is(err, errCorruptPayloadObject) || errors.Is(err, io.ErrUnexpectedEOF) {
		return classified(ErrStorage, StageAcceptMaterial, ReasonMaterialCorrupt)
	}
	return classified(ErrStorage, StageAcceptMaterial, ReasonIO)
}
