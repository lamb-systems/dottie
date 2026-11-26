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

type materialSegment struct {
	summary SegmentSummary
	blob    publication.BlobReference
	payload []byte
	entries []materialEntry
}

type materialAttachment struct {
	segments []materialSegment
}

func (m materialAttachment) summaries() []SegmentSummary {
	summaries := make([]SegmentSummary, 0, len(m.segments))
	for _, segment := range m.segments {
		summaries = append(summaries, segment.summary)
	}
	return summaries
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
	if s.schemaVersion != 4 {
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
	for _, segment := range material.segments {
		if segment.summary.Form != PayloadFormPacked {
			continue
		}
		if validatePayloadForCustody(segment.payload, segment.blob, payloadBasename(segment.payload)) != nil {
			return zeroFloor(), classified(ErrInvalid, StageAcceptMaterial, ReasonRecordSet)
		}
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
	if !bytes.Equal(owner.record, expectedRecord) || !sameSegmentSummaries(owner.segments, material.summaries()) {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	if err := s.openPayloadDirectoryForRead(); err != nil {
		return classifyAcceptedMaterialDirectory(err, stage)
	}
	for _, segment := range material.segments {
		switch segment.summary.Form {
		case PayloadFormPacked:
			name, err := payloadBasenameFromCID(segment.blob.CID)
			if err != nil || !validPayloadBasename(name) {
				return classified(ErrSchema, stage, ReasonCorrupt)
			}
			if _, err := s.inspectPayloadFile(name, nil, segment.blob); err != nil {
				return classifyMaterialCustody(err)
			}
		case PayloadFormFileSet:
			seen := make(map[string]bool, len(segment.entries))
			for _, entry := range segment.entries {
				key := string(entry.blob.CID)
				if seen[key] {
					continue
				}
				seen[key] = true
				if err := s.checkContext(ctx, stage); err != nil {
					return err
				}
				name, err := payloadBasenameFromCID(entry.blob.CID)
				if err != nil || !validPayloadBasename(name) {
					return classified(ErrSchema, stage, ReasonCorrupt)
				}
				if _, err := s.inspectCustodyObject(name, nil, entry.blob, PayloadFormFileSet); err != nil {
					return classifyMaterialCustody(err)
				}
			}
		case PayloadFormSettings:
		default:
			return classified(ErrSchema, stage, ReasonCorrupt)
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
	objects := make(map[string]uint64)
	for _, segment := range material.segments {
		switch segment.summary.Form {
		case PayloadFormPacked:
			objects[payloadBasename(segment.payload)] = segment.blob.Size
		case PayloadFormFileSet:
			for _, entry := range segment.entries {
				name := payloadBasename(entry.content)
				if existing, present := objects[name]; present && existing != entry.blob.Size {
					return classified(ErrInvalid, StageAcceptMaterial, ReasonRecordSet)
				}
				objects[name] = entry.blob.Size
			}
		}
	}
	if err := s.checkPayloadBatchCapacity(ctx, tx, objects, true); err != nil {
		return classified(ErrLimit, StageAcceptMaterial, ReasonCapacity)
	}
	for _, segment := range material.segments {
		switch segment.summary.Form {
		case PayloadFormPacked:
			name := payloadBasename(segment.payload)
			if _, _, err := s.persistPayload(ctx, tx, segment.payload, segment.blob, name); err != nil {
				return classifyMaterialCustody(err)
			}
			if err := cataloguePayload(ctx, tx, segment.blob, name); err != nil {
				return err
			}
		case PayloadFormFileSet:
			seen := make(map[string]bool, len(segment.entries))
			for _, entry := range segment.entries {
				key := string(entry.blob.CID)
				if seen[key] {
					continue
				}
				seen[key] = true
				name := payloadBasename(entry.content)
				if _, _, err := s.persistPayloadObject(ctx, tx, entry.content, entry.blob, name, PayloadFormFileSet); err != nil {
					return classifyMaterialCustody(err)
				}
				if err := cataloguePayload(ctx, tx, entry.blob, name); err != nil {
					return err
				}
			}
		case PayloadFormSettings:
		default:
			return classified(ErrSchema, StageAcceptMaterial, ReasonCorrupt)
		}
	}
	encoded, err := encodeSegmentSummaries(material.summaries())
	if err != nil {
		return classified(ErrSchema, StageAcceptMaterial, ReasonCorrupt)
	}
	if _, err := tx.ExecContext(
		ctx,
		"INSERT INTO accepted_material_refs(accepted_revision,record_cid,segments) VALUES(?,?,?)",
		int64(floor.Revision),
		floor.RecordCID,
		encoded,
	); err != nil {
		return classified(ErrStorage, StageAcceptMaterial, ReasonIO)
	}
	return nil
}

func cataloguePayload(ctx context.Context, tx *sql.Tx, blob publication.BlobReference, name string) error {
	if _, err := tx.ExecContext(
		ctx,
		"INSERT INTO payload_objects(blob_cid,size,basename,logical_bytes) VALUES(?,?,?,?) ON CONFLICT(blob_cid) DO NOTHING",
		blob.CID,
		int64(blob.Size),
		name,
		int64(blob.Size),
	); err != nil {
		return classified(ErrStorage, StageAcceptMaterial, ReasonIO)
	}
	if err := requireCataloguedPayloadObject(ctx, tx, blob, name); err != nil {
		return err
	}
	return nil
}

func (s *Store) checkIncomingFileSetCapacity(ctx context.Context, q queryer, material materialAttachment) error {
	objects := make(map[string]uint64)
	for _, segment := range material.segments {
		for _, entry := range segment.entries {
			name := payloadBasename(entry.content)
			if existing, present := objects[name]; present && existing != entry.blob.Size {
				return classified(ErrInvalid, StageAcceptMaterial, ReasonRecordSet)
			}
			objects[name] = entry.blob.Size
		}
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
