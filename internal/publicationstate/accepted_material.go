package publicationstate

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"

	"github.com/lamb-systems/dottie/internal/publication"
	"golang.org/x/sys/unix"
)

const (
	StageReadAcceptedMaterial Stage  = "read_accepted_material"
	ReasonMaterialNotRetained Reason = "material_not_retained"
	ReasonMaterialMissing     Reason = "material_missing"
	ReasonMaterialCorrupt     Reason = "material_corrupt"
	ReasonMaterialUnsafe      Reason = "material_unsafe"
)

type AcceptedMaterial struct {
	Floor          Floor
	SnapshotRecord []byte
	Payload        []byte
}

func (s *Store) ReadAcceptedMaterial(ctx context.Context, binding Binding, expectedFloor Floor) (AcceptedMaterial, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx == nil {
		return AcceptedMaterial{}, classified(ErrInvalid, StageReadAcceptedMaterial, ReasonContext)
	}
	if err := s.checkContext(ctx, StageReadAcceptedMaterial); err != nil {
		return AcceptedMaterial{}, err
	}
	if err := s.requireReadback(StageReadAcceptedMaterial); err != nil {
		return AcceptedMaterial{}, err
	}
	if validateBinding(binding) != nil || !sameBinding(binding, s.binding) {
		return AcceptedMaterial{}, classified(ErrInvalid, StageReadAcceptedMaterial, ReasonBinding)
	}
	state, err := s.readState(ctx, s.conn, StageReadAcceptedMaterial)
	if err != nil {
		return AcceptedMaterial{}, err
	}
	if state.floor == nil {
		return AcceptedMaterial{}, classified(ErrContinuity, StageReadAcceptedMaterial, ReasonFirstUseRequired)
	}
	if err := validateExpectedAcceptedFloor(expectedFloor, s.binding, s.limits); err != nil {
		return AcceptedMaterial{}, err
	}
	if !sameAcceptedFloor(*state.floor, expectedFloor) {
		return AcceptedMaterial{}, classified(ErrContinuity, StageReadAcceptedMaterial, ReasonStale)
	}
	basename, record, blob, err := s.acceptedMaterialOwner(ctx, *state.floor)
	if err != nil {
		return AcceptedMaterial{}, err
	}
	if err := s.openPayloadDirectoryForRead(); err != nil {
		return AcceptedMaterial{}, classifyAcceptedMaterialDirectory(err)
	}
	payload, err := s.inspectPayloadFile(basename, nil, blob)
	if err != nil {
		return AcceptedMaterial{}, classifyAcceptedMaterialRead(err)
	}
	if err := s.checkContext(ctx, StageReadAcceptedMaterial); err != nil {
		return AcceptedMaterial{}, err
	}
	return AcceptedMaterial{Floor: cloneFloor(*state.floor), SnapshotRecord: bytes.Clone(record), Payload: payload}, nil
}

func validateExpectedAcceptedFloor(floor Floor, binding Binding, limits Limits) error {
	if validateBinding(floor.Binding) != nil || !sameBinding(floor.Binding, binding) {
		return classified(ErrInvalid, StageReadAcceptedMaterial, ReasonBinding)
	}
	if len(floor.AnchorCID) == 0 || len(floor.AnchorCID) > publication.MaxCIDBytes || len(floor.Head) == 0 || len(floor.Head) > publication.MaxRecordBytes || len(floor.RecordCID) == 0 || len(floor.RecordCID) > publication.MaxCIDBytes || len(floor.BlobCID) == 0 || len(floor.BlobCID) > publication.MaxCIDBytes || len(floor.SnapshotKey) != publication.SequenceKeyLength || (floor.Provenance != ProvenanceFirst && floor.Provenance != ProvenanceReplace) || allZero(floor.DatabaseID[:]) {
		return classified(ErrInvalid, StageReadAcceptedMaterial, ReasonRecordSet)
	}
	if err := validatePersistedFloor(floor, binding, floor.DatabaseID, limits); err != nil {
		return classified(ErrInvalid, StageReadAcceptedMaterial, ReasonRecordSet)
	}
	return nil
}

func sameAcceptedFloor(left, right Floor) bool {
	return left.DatabaseID == right.DatabaseID &&
		left.Revision == right.Revision &&
		left.Generation == right.Generation &&
		left.Provenance == right.Provenance &&
		bytes.Equal(left.AnchorCID, right.AnchorCID) &&
		sameBinding(left.Binding, right.Binding) &&
		sameAcceptedContext(left.SuppliedContext, right.SuppliedContext) &&
		bytes.Equal(left.Head, right.Head) &&
		left.SnapshotKey == right.SnapshotKey &&
		left.Sequence == right.Sequence &&
		left.PublicationID == right.PublicationID &&
		bytes.Equal(left.RecordCID, right.RecordCID) &&
		bytes.Equal(left.BlobCID, right.BlobCID) &&
		left.BlobSize == right.BlobSize &&
		left.ObservationDigest == right.ObservationDigest &&
		left.AcceptedEventDigest == right.AcceptedEventDigest
}

func sameAcceptedContext(left, right SuppliedContext) bool {
	if left.RepositoryRevision != right.RepositoryRevision || !bytes.Equal(left.RepositoryDigest, right.RepositoryDigest) {
		return false
	}
	if left.Policy == nil || right.Policy == nil {
		return left.Policy == nil && right.Policy == nil
	}
	return left.Policy.Revision == right.Policy.Revision && left.Policy.OwnerOnly == right.Policy.OwnerOnly && bytes.Equal(left.Policy.Identity, right.Policy.Identity)
}

func (s *Store) acceptedMaterialOwner(ctx context.Context, floor Floor) (string, []byte, publication.BlobReference, error) {
	count, err := queryInt64(ctx, s.conn, "SELECT COUNT(*) FROM retained_publications WHERE accepted_revision=?", int64(floor.Revision))
	if err != nil {
		return "", nil, publication.BlobReference{}, queryReadError(ctx, StageReadAcceptedMaterial, err)
	}
	if count == 0 {
		return "", nil, publication.BlobReference{}, classified(ErrStorage, StageReadAcceptedMaterial, ReasonMaterialNotRetained)
	}
	if count != 1 {
		return "", nil, publication.BlobReference{}, classified(ErrSchema, StageReadAcceptedMaterial, ReasonCorrupt)
	}

	var idValue, idLengthValue, recordValue, recordLengthValue, blobValue, blobLengthValue any
	var sequenceValue, sizeValue, revisionValue any
	var lifecycleValue, lifecycleLengthValue, outcomeValue, outcomeLengthValue, blockedValue, blockedLengthValue any
	var recordKeyValue, recordKeyLengthValue, recordSequenceValue any
	var objectCIDValue, objectCIDLengthValue, objectSizeValue, basenameValue, basenameLengthValue any
	err = s.conn.QueryRowContext(ctx, `SELECT
		substr(rp.attempt_id,1,17),length(rp.attempt_id),
		substr(rp.record_cid,1,129),length(rp.record_cid),
		substr(rp.blob_cid,1,129),length(rp.blob_cid),rp.sequence,rp.size,rp.accepted_revision,
		substr(pa.lifecycle,1,65),length(pa.lifecycle),substr(pa.outcome,1,65),length(pa.outcome),substr(pa.blocked,1,65),length(pa.blocked),
		substr(ar.record_key,1,17),length(ar.record_key),ar.sequence,
		substr(po.blob_cid,1,129),length(po.blob_cid),po.size,substr(po.basename,1,73),length(po.basename)
		FROM retained_publications rp
		JOIN publication_attempts pa ON pa.attempt_id=rp.attempt_id
		JOIN accepted_events ae ON ae.revision=rp.accepted_revision
		JOIN accepted_records ar ON ar.cid=rp.record_cid
		JOIN payload_objects po ON po.blob_cid=rp.blob_cid
		WHERE rp.accepted_revision=?`, int64(floor.Revision)).Scan(
		&idValue, &idLengthValue, &recordValue, &recordLengthValue, &blobValue, &blobLengthValue, &sequenceValue, &sizeValue, &revisionValue,
		&lifecycleValue, &lifecycleLengthValue, &outcomeValue, &outcomeLengthValue, &blockedValue, &blockedLengthValue,
		&recordKeyValue, &recordKeyLengthValue, &recordSequenceValue,
		&objectCIDValue, &objectCIDLengthValue, &objectSizeValue, &basenameValue, &basenameLengthValue)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil, publication.BlobReference{}, classified(ErrSchema, StageReadAcceptedMaterial, ReasonCorrupt)
		}
		return "", nil, publication.BlobReference{}, storageFailure(ctx, StageReadAcceptedMaterial, err)
	}

	attemptID, idOK := rawBytes(idValue)
	idLength, idLengthOK := rawInt64(idLengthValue)
	recordCID, recordOK := rawBytes(recordValue)
	recordLength, recordLengthOK := rawInt64(recordLengthValue)
	blobCID, blobOK := rawBytes(blobValue)
	blobLength, blobLengthOK := rawInt64(blobLengthValue)
	sequence, sequenceOK := rawInt64(sequenceValue)
	size, sizeOK := rawInt64(sizeValue)
	revision, revisionOK := rawInt64(revisionValue)
	lifecycle, lifecycleOK := lifecycleValue.(string)
	lifecycleLength, lifecycleLengthOK := rawInt64(lifecycleLengthValue)
	outcome, outcomeOK := outcomeValue.(string)
	outcomeLength, outcomeLengthOK := rawInt64(outcomeLengthValue)
	blocked, blockedOK := blockedValue.(string)
	blockedLength, blockedLengthOK := rawInt64(blockedLengthValue)
	recordKey, recordKeyOK := recordKeyValue.(string)
	recordKeyLength, recordKeyLengthOK := rawInt64(recordKeyLengthValue)
	recordSequence, recordSequenceOK := rawInt64(recordSequenceValue)
	objectCID, objectCIDOK := rawBytes(objectCIDValue)
	objectCIDLength, objectCIDLengthOK := rawInt64(objectCIDLengthValue)
	objectSize, objectSizeOK := rawInt64(objectSizeValue)
	basename, basenameOK := basenameValue.(string)
	basenameLength, basenameLengthOK := rawInt64(basenameLengthValue)
	if !idOK || !idLengthOK || idLength != 16 || len(attemptID) != 16 ||
		!recordOK || !recordLengthOK || recordLength <= 0 || recordLength > publication.MaxCIDBytes || int64(len(recordCID)) != recordLength ||
		!blobOK || !blobLengthOK || blobLength <= 0 || blobLength > publication.MaxCIDBytes || int64(len(blobCID)) != blobLength ||
		!sequenceOK || sequence < 0 || uint64(sequence) != floor.Sequence ||
		!sizeOK || size <= 0 || uint64(size) != floor.BlobSize ||
		!revisionOK || revision <= 0 || uint64(revision) != floor.Revision ||
		!lifecycleOK || !lifecycleLengthOK || lifecycleLength <= 0 || lifecycleLength > 64 || lifecycle != string(AttemptRetiredSuccess) ||
		!outcomeOK || !outcomeLengthOK || outcomeLength <= 0 || outcomeLength > 64 || outcome != string(OutcomeCurrent) ||
		!blockedOK || !blockedLengthOK || blockedLength != 0 || blocked != "" ||
		!recordKeyOK || !recordKeyLengthOK || recordKeyLength != publication.SequenceKeyLength || recordKey != floor.SnapshotKey ||
		!recordSequenceOK || recordSequence < 0 || uint64(recordSequence) != floor.Sequence ||
		!objectCIDOK || !objectCIDLengthOK || objectCIDLength <= 0 || objectCIDLength > publication.MaxCIDBytes || int64(len(objectCID)) != objectCIDLength ||
		!objectSizeOK || objectSize <= 0 || uint64(objectSize) != floor.BlobSize ||
		!basenameOK || !basenameLengthOK || basenameLength != 72 || int64(len(basename)) != basenameLength ||
		!bytes.Equal(recordCID, floor.RecordCID) || !bytes.Equal(blobCID, floor.BlobCID) || !bytes.Equal(objectCID, floor.BlobCID) {
		return "", nil, publication.BlobReference{}, classified(ErrSchema, StageReadAcceptedMaterial, ReasonCorrupt)
	}

	var id [16]byte
	copy(id[:], attemptID)
	attempt, err := s.loadStoredAttempt(ctx, s.conn, id, StageReadAcceptedMaterial)
	if err != nil {
		return "", nil, publication.BlobReference{}, err
	}
	if attempt.lifecycle != AttemptRetiredSuccess || attempt.outcome != OutcomeCurrent || attempt.blocked != "" ||
		!bytes.Equal(attempt.core.SnapshotCID, floor.RecordCID) || !bytes.Equal(attempt.core.BlobCID, floor.BlobCID) ||
		attempt.core.BlobSize != floor.BlobSize || attempt.core.SnapshotKey != floor.SnapshotKey {
		return "", nil, publication.BlobReference{}, classified(ErrSchema, StageReadAcceptedMaterial, ReasonCorrupt)
	}

	record, err := s.loadRecordByCID(ctx, s.conn, floor.RecordCID, floor.SnapshotKey, floor.Sequence, StageReadAcceptedMaterial)
	if err != nil {
		return "", nil, publication.BlobReference{}, err
	}
	snapshot, err := publication.DecodeSnapshot(record.raw)
	if err != nil || snapshot.Vault != floor.Binding.Vault || snapshot.PublicationSeq != floor.Sequence || snapshot.PublicationID != floor.PublicationID ||
		!bytes.Equal(snapshot.Blob.CID, floor.BlobCID) || snapshot.Blob.Size != floor.BlobSize ||
		!bytes.Equal(attempt.core.SnapshotRecord, record.raw) {
		return "", nil, publication.BlobReference{}, classified(ErrSchema, StageReadAcceptedMaterial, ReasonCorrupt)
	}
	wantedBasename, err := payloadBasenameFromCID(floor.BlobCID)
	if err != nil || !validPayloadBasename(basename) || basename != wantedBasename {
		return "", nil, publication.BlobReference{}, classified(ErrSchema, StageReadAcceptedMaterial, ReasonCorrupt)
	}
	return basename, record.raw, publication.BlobReference{CID: bytes.Clone(floor.BlobCID), Size: floor.BlobSize}, nil
}

func classifyAcceptedMaterialDirectory(err error) error {
	if errors.Is(err, unix.ENOENT) {
		return classified(ErrStorage, StageReadAcceptedMaterial, ReasonMaterialMissing)
	}
	return classified(ErrStorage, StageReadAcceptedMaterial, ReasonIO)
}

func classifyAcceptedMaterialRead(err error) error {
	if errors.Is(err, unix.ENOENT) {
		return classified(ErrStorage, StageReadAcceptedMaterial, ReasonMaterialMissing)
	}
	if errors.Is(err, errUnsafePayloadObject) || errors.Is(err, unix.ELOOP) {
		return classified(ErrStorage, StageReadAcceptedMaterial, ReasonMaterialUnsafe)
	}
	if errors.Is(err, errCorruptPayloadObject) || errors.Is(err, io.ErrUnexpectedEOF) {
		return classified(ErrStorage, StageReadAcceptedMaterial, ReasonMaterialCorrupt)
	}
	return classified(ErrStorage, StageReadAcceptedMaterial, ReasonIO)
}
