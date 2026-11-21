package publicationstate

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"

	"golang.org/x/sys/unix"

	"github.com/lamb-systems/dottie/internal/publication"
)

const (
	StageReadAcceptedMaterial Stage  = "read_accepted_material"
	ReasonMaterialNotRetained Reason = "material_not_retained"
	ReasonMaterialMissing     Reason = "material_missing"
	ReasonMaterialCorrupt     Reason = "material_corrupt"
	ReasonMaterialUnsafe      Reason = "material_unsafe"
)

type AcceptedMaterialEntry struct {
	Path    string
	Mode    uint32
	Content []byte
}

type AcceptedMaterial struct {
	Floor          Floor
	SnapshotRecord []byte
	Payload        []byte
	Entries        []AcceptedMaterialEntry
}

type materialOwnership struct {
	form     PayloadForm
	name     string
	record   []byte
	blob     publication.BlobReference
	manifest *ManifestPayload
}

func (s *Store) ReadAcceptedMaterial(
	ctx context.Context,
	binding Binding,
	expectedFloor Floor,
) (AcceptedMaterial, error) {
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
	if err := validateExpectedAcceptedFloor(expectedFloor, s.binding, s.limits, StageReadAcceptedMaterial); err != nil {
		return AcceptedMaterial{}, err
	}
	if !sameAcceptedFloor(*state.floor, expectedFloor) {
		return AcceptedMaterial{}, classified(ErrContinuity, StageReadAcceptedMaterial, ReasonStale)
	}
	owner, err := s.acceptedMaterialOwner(ctx, s.conn, *state.floor, StageReadAcceptedMaterial)
	if err != nil {
		return AcceptedMaterial{}, err
	}
	if err := s.openPayloadDirectoryForRead(); err != nil {
		return AcceptedMaterial{}, classifyAcceptedMaterialDirectory(err, StageReadAcceptedMaterial)
	}
	if owner.form == PayloadFormManifest {
		entries, err := s.readAcceptedManifestEntries(ctx, owner, StageReadAcceptedMaterial)
		if err != nil {
			return AcceptedMaterial{}, err
		}
		if err := s.checkContext(ctx, StageReadAcceptedMaterial); err != nil {
			return AcceptedMaterial{}, err
		}
		return AcceptedMaterial{
			Floor:          cloneFloor(*state.floor),
			SnapshotRecord: bytes.Clone(owner.record),
			Entries:        entries,
		}, nil
	}
	payload, err := s.inspectPayloadFile(owner.name, nil, owner.blob)
	if err != nil {
		return AcceptedMaterial{}, classifyAcceptedMaterialRead(err, StageReadAcceptedMaterial)
	}
	if err := s.checkContext(ctx, StageReadAcceptedMaterial); err != nil {
		return AcceptedMaterial{}, err
	}
	return AcceptedMaterial{Floor: cloneFloor(*state.floor), SnapshotRecord: bytes.Clone(owner.record), Payload: payload}, nil
}

func (s *Store) readAcceptedManifestEntries(
	ctx context.Context,
	owner materialOwnership,
	stage Stage,
) ([]AcceptedMaterialEntry, error) {
	snapshot, err := publication.DecodeSnapshot(owner.record)
	if err != nil || payloadFormOf(snapshot) != PayloadFormManifest ||
		!manifestPayloadMatchesRecord(owner.manifest, snapshot) {
		return nil, classified(ErrSchema, stage, ReasonCorrupt)
	}
	contents := make(map[string][]byte, len(snapshot.Entries))
	entries := make([]AcceptedMaterialEntry, 0, len(snapshot.Entries))
	for _, entry := range snapshot.Entries {
		if err := s.checkContext(ctx, stage); err != nil {
			return nil, err
		}
		key := string(entry.Blob.CID) + "\x00" + fmt.Sprint(entry.Size)
		content, present := contents[key]
		if !present {
			name, nameErr := payloadBasenameFromCID(entry.Blob.CID)
			if nameErr != nil || !validPayloadBasename(name) {
				return nil, classified(ErrSchema, stage, ReasonCorrupt)
			}
			blob := publication.BlobReference{
				CID:      bytes.Clone(entry.Blob.CID),
				Size:     entry.Size,
				MIMEType: entry.Blob.MIMEType,
			}
			data, readErr := s.inspectCustodyObject(name, nil, blob, PayloadFormManifest)
			if readErr != nil {
				return nil, classifyAcceptedMaterialRead(readErr, stage)
			}
			content = data
			contents[key] = data
		}
		entries = append(entries, AcceptedMaterialEntry{
			Path:    entry.Path,
			Mode:    entry.Mode,
			Content: bytes.Clone(content),
		})
	}
	return entries, nil
}

func validateExpectedAcceptedFloor(floor Floor, binding Binding, limits Limits, stage Stage) error {
	if validateBinding(floor.Binding) != nil || !sameBinding(floor.Binding, binding) {
		return classified(ErrInvalid, stage, ReasonBinding)
	}
	if len(floor.AnchorCID) == 0 || len(floor.AnchorCID) > publication.MaxCIDBytes || len(floor.Head) == 0 ||
		len(floor.Head) > publication.MaxRecordBytes ||
		len(floor.RecordCID) == 0 ||
		len(floor.RecordCID) > publication.MaxCIDBytes ||
		len(floor.SnapshotKey) != publication.SequenceKeyLength ||
		(floor.Provenance != ProvenanceFirst && floor.Provenance != ProvenanceReplace) ||
		allZero(floor.DatabaseID[:]) {
		return classified(ErrInvalid, stage, ReasonRecordSet)
	}
	if err := validatePersistedFloor(floor, binding, floor.DatabaseID, limits); err != nil {
		return classified(ErrInvalid, stage, ReasonRecordSet)
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
		sameManifestPayload(left.Manifest, right.Manifest) &&
		left.ObservationDigest == right.ObservationDigest &&
		left.AcceptedEventDigest == right.AcceptedEventDigest
}

func sameAcceptedContext(left, right SuppliedContext) bool {
	if left.RepositoryRevision != right.RepositoryRevision ||
		!bytes.Equal(left.RepositoryDigest, right.RepositoryDigest) {
		return false
	}
	if left.Policy == nil || right.Policy == nil {
		return left.Policy == nil && right.Policy == nil
	}
	return left.Policy.Revision == right.Policy.Revision && left.Policy.OwnerOnly == right.Policy.OwnerOnly &&
		bytes.Equal(left.Policy.Identity, right.Policy.Identity)
}

func (s *Store) acceptedMaterialOwner(
	ctx context.Context,
	q queryer,
	floor Floor,
	stage Stage,
) (materialOwnership, error) {
	count, err := queryInt64(
		ctx,
		q,
		"SELECT COUNT(*) FROM retained_publications WHERE accepted_revision=?",
		int64(floor.Revision),
	)
	if err != nil {
		return materialOwnership{}, queryReadError(ctx, stage, err)
	}
	if count < 0 || count > 1 {
		return materialOwnership{}, classified(ErrSchema, stage, ReasonCorrupt)
	}

	incomingCount := int64(0)
	if s.schemaVersion == 3 {
		incomingCount, err = queryInt64(
			ctx,
			q,
			"SELECT COUNT(*) FROM accepted_material_refs WHERE accepted_revision=?",
			int64(floor.Revision),
		)
		if err != nil {
			return materialOwnership{}, queryReadError(ctx, stage, err)
		}
		if incomingCount < 0 || incomingCount > 1 {
			return materialOwnership{}, classified(ErrSchema, stage, ReasonCorrupt)
		}
	}
	if count == 1 && incomingCount == 1 {
		return materialOwnership{}, classified(ErrSchema, stage, ReasonCorrupt)
	}
	if count == 0 && incomingCount == 0 {
		return materialOwnership{}, classified(ErrStorage, stage, ReasonMaterialNotRetained)
	}
	if count == 1 {
		return s.finalizedAcceptedMaterialOwner(ctx, q, floor, stage)
	}
	return s.incomingAcceptedMaterialOwner(ctx, q, floor, stage)
}

func (s *Store) finalizedAcceptedMaterialOwner(
	ctx context.Context,
	q queryer,
	floor Floor,
	stage Stage,
) (materialOwnership, error) {
	var idValue, idLengthValue, recordValue, recordLengthValue any
	var formTypeValue, formValue, formLengthValue any
	var blobTypeValue, blobValue, blobLengthValue any
	var sizeTypeValue, sizeValue any
	var manifestTypeValue, manifestLengthValue any
	var sequenceValue, revisionValue any
	var lifecycleValue, lifecycleLengthValue, outcomeValue, outcomeLengthValue, blockedValue, blockedLengthValue any
	var recordKeyValue, recordKeyLengthValue, recordSequenceValue any
	var objectCIDValue, objectCIDLengthValue, objectSizeValue, basenameValue, basenameLengthValue any
	err := q.QueryRowContext(ctx, `SELECT
		substr(rp.attempt_id,1,17),length(rp.attempt_id),
		substr(rp.record_cid,1,129),length(rp.record_cid),
		typeof(rp.form),CASE WHEN typeof(rp.form)='text' THEN substr(rp.form,1,8) END,length(CAST(rp.form AS BLOB)),
		typeof(rp.blob_cid),substr(rp.blob_cid,1,129),length(rp.blob_cid),
		typeof(rp.size),CASE WHEN typeof(rp.size)='integer' THEN rp.size END,
		typeof(rp.manifest),length(CAST(rp.manifest AS BLOB)),
		rp.sequence,rp.accepted_revision,
		substr(pa.lifecycle,1,65),length(pa.lifecycle),substr(pa.outcome,1,65),length(pa.outcome),substr(pa.blocked,1,65),length(pa.blocked),
		substr(ar.record_key,1,17),length(ar.record_key),ar.sequence,
		substr(po.blob_cid,1,129),length(po.blob_cid),po.size,substr(po.basename,1,73),length(po.basename)
		FROM retained_publications rp
		JOIN publication_attempts pa ON pa.attempt_id=rp.attempt_id
		JOIN accepted_events ae ON ae.revision=rp.accepted_revision
		JOIN accepted_records ar ON ar.cid=rp.record_cid
		LEFT JOIN payload_objects po ON po.blob_cid=rp.blob_cid
		WHERE rp.accepted_revision=?`, int64(floor.Revision)).Scan(
		&idValue, &idLengthValue, &recordValue, &recordLengthValue,
		&formTypeValue, &formValue, &formLengthValue,
		&blobTypeValue, &blobValue, &blobLengthValue,
		&sizeTypeValue, &sizeValue,
		&manifestTypeValue, &manifestLengthValue,
		&sequenceValue, &revisionValue,
		&lifecycleValue, &lifecycleLengthValue, &outcomeValue, &outcomeLengthValue, &blockedValue, &blockedLengthValue,
		&recordKeyValue, &recordKeyLengthValue, &recordSequenceValue,
		&objectCIDValue, &objectCIDLengthValue, &objectSizeValue, &basenameValue, &basenameLengthValue)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return materialOwnership{}, classified(ErrSchema, stage, ReasonCorrupt)
		}
		return materialOwnership{}, storageFailure(ctx, stage, err)
	}

	attemptID, idOK := rawBytes(idValue)
	idLength, idLengthOK := rawInt64(idLengthValue)
	recordCID, recordOK := rawBytes(recordValue)
	recordLength, recordLengthOK := rawInt64(recordLengthValue)
	formType, formTypeOK := formTypeValue.(string)
	form, formOK := formValue.(string)
	formLength, formLengthOK := rawInt64(formLengthValue)
	blobType, blobTypeOK := blobTypeValue.(string)
	blobCID, blobOK := rawBytes(blobValue)
	blobLength, blobLengthOK := rawInt64(blobLengthValue)
	sizeType, sizeTypeOK := sizeTypeValue.(string)
	size, sizeOK := rawInt64(sizeValue)
	manifestType, manifestTypeOK := manifestTypeValue.(string)
	manifestLength, manifestLengthOK := rawInt64(manifestLengthValue)
	sequence, sequenceOK := rawInt64(sequenceValue)
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
		!formTypeOK || formType != "text" || !formOK || !formLengthOK || formLength != int64(len(form)) ||
		!sequenceOK || sequence < 0 || uint64(sequence) != floor.Sequence ||
		!revisionOK || revision <= 0 || uint64(revision) != floor.Revision ||
		!lifecycleOK || !lifecycleLengthOK || lifecycleLength <= 0 || lifecycleLength > 64 || lifecycle != string(AttemptRetiredSuccess) ||
		!outcomeOK || !outcomeLengthOK || outcomeLength <= 0 || outcomeLength > 64 || outcome != string(OutcomeCurrent) ||
		!blockedOK || !blockedLengthOK || blockedLength != 0 || blocked != "" ||
		!recordKeyOK || !recordKeyLengthOK || recordKeyLength != publication.SequenceKeyLength || recordKey != floor.SnapshotKey ||
		!recordSequenceOK || recordSequence < 0 || uint64(recordSequence) != floor.Sequence ||
		!bytes.Equal(recordCID, floor.RecordCID) {
		return materialOwnership{}, classified(ErrSchema, stage, ReasonCorrupt)
	}
	owner := materialOwnership{
		form:   PayloadForm(form),
		record: nil,
	}
	switch owner.form {
	case PayloadFormPacked:
		if !blobTypeOK || blobType != "blob" || !blobOK || !blobLengthOK || blobLength <= 0 ||
			blobLength > publication.MaxCIDBytes || int64(len(blobCID)) != blobLength ||
			!sizeTypeOK || sizeType != "integer" || !sizeOK || size <= 0 || uint64(size) != floor.BlobSize ||
			!manifestTypeOK || manifestType != "null" ||
			!objectCIDOK || !objectCIDLengthOK || objectCIDLength <= 0 || objectCIDLength > publication.MaxCIDBytes ||
			int64(len(objectCID)) != objectCIDLength ||
			!objectSizeOK || objectSize <= 0 || uint64(objectSize) != floor.BlobSize ||
			!basenameOK || !basenameLengthOK || basenameLength != 72 || int64(len(basename)) != basenameLength ||
			!bytes.Equal(blobCID, floor.BlobCID) || !bytes.Equal(objectCID, floor.BlobCID) {
			return materialOwnership{}, classified(ErrSchema, stage, ReasonCorrupt)
		}
		wantedBasename, nameErr := payloadBasenameFromCID(floor.BlobCID)
		if nameErr != nil || !validPayloadBasename(basename) || basename != wantedBasename {
			return materialOwnership{}, classified(ErrSchema, stage, ReasonCorrupt)
		}
		owner.name = basename
		owner.blob = publication.BlobReference{
			CID:      bytes.Clone(floor.BlobCID),
			Size:     floor.BlobSize,
			MIMEType: publication.SnapshotBlobMIMEType,
		}
	case PayloadFormManifest:
		if blobType != "null" || sizeType != "null" || floor.Manifest == nil || len(floor.BlobCID) != 0 ||
			floor.BlobSize != 0 ||
			!manifestTypeOK || manifestType != "blob" || !manifestLengthOK || manifestLength <= 0 ||
			manifestLength > publication.MaxManifestRecordBytes ||
			objectCIDOK || objectCIDLengthOK || objectSizeOK || basenameOK {
			return materialOwnership{}, classified(ErrSchema, stage, ReasonCorrupt)
		}
		expected, err := encodeRetainedManifest(floor.Manifest)
		if err != nil {
			return materialOwnership{}, classified(ErrSchema, stage, ReasonCorrupt)
		}
		stored, err := queryInt64(
			ctx,
			q,
			"SELECT COUNT(*) FROM retained_publications WHERE accepted_revision=? AND manifest=?",
			int64(floor.Revision),
			expected,
		)
		if err != nil {
			return materialOwnership{}, queryReadError(ctx, stage, err)
		}
		if stored != 1 {
			return materialOwnership{}, classified(ErrSchema, stage, ReasonCorrupt)
		}
		owner.manifest = cloneManifestPayload(floor.Manifest)
	default:
		return materialOwnership{}, classified(ErrSchema, stage, ReasonCorrupt)
	}

	var id [16]byte
	copy(id[:], attemptID)
	attempt, err := s.loadStoredAttempt(ctx, q, id, stage)
	if err != nil {
		return materialOwnership{}, err
	}
	if attempt.lifecycle != AttemptRetiredSuccess || attempt.outcome != OutcomeCurrent || attempt.blocked != "" ||
		attemptCoreForm(attempt.core) != owner.form ||
		!bytes.Equal(attempt.core.SnapshotCID, floor.RecordCID) || attempt.core.SnapshotKey != floor.SnapshotKey {
		return materialOwnership{}, classified(ErrSchema, stage, ReasonCorrupt)
	}
	if owner.form == PayloadFormPacked &&
		(!bytes.Equal(attempt.core.BlobCID, floor.BlobCID) || attempt.core.BlobSize != floor.BlobSize) {
		return materialOwnership{}, classified(ErrSchema, stage, ReasonCorrupt)
	}

	record, err := s.loadRecordByCID(ctx, q, floor.RecordCID, floor.SnapshotKey, floor.Sequence, stage)
	if err != nil {
		return materialOwnership{}, err
	}
	snapshot, err := publication.DecodeSnapshot(record.raw)
	if err != nil || snapshot.Vault != floor.Binding.Vault || snapshot.PublicationSeq != floor.Sequence ||
		snapshot.PublicationID != floor.PublicationID ||
		!floorPayloadMatchesRecord(floor, snapshot) ||
		!bytes.Equal(attempt.core.SnapshotRecord, record.raw) {
		return materialOwnership{}, classified(ErrSchema, stage, ReasonCorrupt)
	}
	owner.record = bytes.Clone(record.raw)
	return owner, nil
}

func (s *Store) incomingAcceptedMaterialOwner(
	ctx context.Context,
	q queryer,
	floor Floor,
	stage Stage,
) (materialOwnership, error) {
	var revisionTypeValue, revisionValue, recordTypeValue, recordLengthValue, recordValue any
	var formTypeValue, formValue, formLengthValue any
	var blobTypeValue, blobLengthValue, blobValue any
	var manifestTypeValue, manifestLengthValue any
	err := q.QueryRowContext(ctx, "SELECT typeof(accepted_revision),CASE WHEN typeof(accepted_revision)='integer' THEN accepted_revision END,typeof(record_cid),length(CAST(record_cid AS BLOB)),substr(CAST(record_cid AS BLOB),1,129),typeof(form),CASE WHEN typeof(form)='text' THEN substr(form,1,8) END,length(CAST(form AS BLOB)),typeof(blob_cid),length(CAST(blob_cid AS BLOB)),substr(CAST(blob_cid AS BLOB),1,129),typeof(manifest),length(CAST(manifest AS BLOB)) FROM accepted_material_refs WHERE accepted_revision=?", int64(floor.Revision)).
		Scan(
			&revisionTypeValue, &revisionValue, &recordTypeValue, &recordLengthValue, &recordValue,
			&formTypeValue, &formValue, &formLengthValue,
			&blobTypeValue, &blobLengthValue, &blobValue,
			&manifestTypeValue, &manifestLengthValue)
	if errors.Is(err, sql.ErrNoRows) {
		return materialOwnership{}, classified(ErrSchema, stage, ReasonCorrupt)
	}
	if err != nil {
		return materialOwnership{}, storageFailure(ctx, stage, err)
	}
	revisionType, revisionTypeOK := revisionTypeValue.(string)
	revision, revisionOK := rawInt64(revisionValue)
	recordType, recordTypeOK := recordTypeValue.(string)
	recordLength, recordLengthOK := rawInt64(recordLengthValue)
	recordCID, recordOK := rawBytes(recordValue)
	formType, formTypeOK := formTypeValue.(string)
	form, formOK := formValue.(string)
	formLength, formLengthOK := rawInt64(formLengthValue)
	blobType, blobTypeOK := blobTypeValue.(string)
	blobLength, blobLengthOK := rawInt64(blobLengthValue)
	blobCID, blobOK := rawBytes(blobValue)
	manifestType, manifestTypeOK := manifestTypeValue.(string)
	manifestLength, manifestLengthOK := rawInt64(manifestLengthValue)
	if !revisionTypeOK ||
		revisionType != "integer" ||
		!revisionOK ||
		revision < 1 ||
		uint64(revision) != floor.Revision ||
		!recordTypeOK ||
		recordType != "blob" ||
		!recordLengthOK ||
		recordLength < 1 ||
		recordLength > publication.MaxCIDBytes ||
		!recordOK ||
		int64(len(recordCID)) != recordLength ||
		!formTypeOK ||
		formType != "text" ||
		!formOK ||
		!formLengthOK ||
		formLength != int64(len(form)) ||
		!bytes.Equal(recordCID, floor.RecordCID) {
		return materialOwnership{}, classified(ErrSchema, stage, ReasonCorrupt)
	}
	ref := incomingMaterialRef{
		revision:  revision,
		recordCID: bytes.Clone(recordCID),
		form:      PayloadForm(form),
	}
	switch ref.form {
	case PayloadFormPacked:
		if !blobTypeOK || blobType != "blob" || !blobLengthOK || blobLength < 1 ||
			blobLength > publication.MaxCIDBytes || !blobOK || int64(len(blobCID)) != blobLength ||
			!manifestTypeOK || manifestType != "null" || !bytes.Equal(blobCID, floor.BlobCID) {
			return materialOwnership{}, classified(ErrSchema, stage, ReasonCorrupt)
		}
		ref.blobCID = bytes.Clone(blobCID)
	case PayloadFormManifest:
		if blobType != "null" || !manifestTypeOK || manifestType != "blob" || !manifestLengthOK ||
			manifestLength < 1 || manifestLength > publication.MaxManifestRecordBytes || floor.Manifest == nil ||
			len(floor.BlobCID) != 0 || floor.BlobSize != 0 {
			return materialOwnership{}, classified(ErrSchema, stage, ReasonCorrupt)
		}
		ref.manifestLength = manifestLength
	default:
		return materialOwnership{}, classified(ErrSchema, stage, ReasonCorrupt)
	}
	if err := s.checkIncomingMaterialRef(ctx, q, ref, stage, make(manifestCatalogCache)); err != nil {
		return materialOwnership{}, err
	}
	record, err := s.loadRecordByCID(ctx, q, floor.RecordCID, floor.SnapshotKey, floor.Sequence, stage)
	if err != nil {
		return materialOwnership{}, err
	}
	snapshot, err := publication.DecodeSnapshot(record.raw)
	if err != nil || payloadFormOf(snapshot) != ref.form || !floorPayloadMatchesRecord(floor, snapshot) {
		return materialOwnership{}, classified(ErrSchema, stage, ReasonCorrupt)
	}
	owner := materialOwnership{form: ref.form, record: bytes.Clone(record.raw)}
	if ref.form == PayloadFormManifest {
		owner.manifest = cloneManifestPayload(floor.Manifest)
		return owner, nil
	}
	basename, err := payloadBasenameFromCID(floor.BlobCID)
	if err != nil || !validPayloadBasename(basename) {
		return materialOwnership{}, classified(ErrSchema, stage, ReasonCorrupt)
	}
	owner.name = basename
	owner.blob = publication.BlobReference{
		CID:      bytes.Clone(floor.BlobCID),
		Size:     floor.BlobSize,
		MIMEType: publication.SnapshotBlobMIMEType,
	}
	return owner, nil
}

func classifyAcceptedMaterialDirectory(err error, stage Stage) error {
	if errors.Is(err, unix.ENOENT) {
		return classified(ErrStorage, stage, ReasonMaterialMissing)
	}
	return classified(ErrStorage, stage, ReasonIO)
}

func classifyAcceptedMaterialRead(err error, stage Stage) error {
	if errors.Is(err, unix.ENOENT) {
		return classified(ErrStorage, stage, ReasonMaterialMissing)
	}
	if errors.Is(err, errUnsafePayloadObject) || errors.Is(err, unix.ELOOP) {
		return classified(ErrStorage, stage, ReasonMaterialUnsafe)
	}
	if errors.Is(err, errCorruptPayloadObject) || errors.Is(err, io.ErrUnexpectedEOF) {
		return classified(ErrStorage, stage, ReasonMaterialCorrupt)
	}
	return classified(ErrStorage, stage, ReasonIO)
}
