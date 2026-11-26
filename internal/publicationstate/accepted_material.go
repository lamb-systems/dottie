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
	Segments       []AcceptedMaterialSegment
}

type AcceptedMaterialSegment struct {
	Summary SegmentSummary
	Blob    []byte
	Entries []AcceptedMaterialEntry
}

type materialOwnership struct {
	segments []SegmentSummary
	record   []byte
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
	snapshot, err := publication.DecodeSnapshot(owner.record)
	if err != nil || !sameSegmentSummaries(summariesOfRecord(snapshot.Segments), owner.segments) {
		return AcceptedMaterial{}, classified(ErrSchema, StageReadAcceptedMaterial, ReasonCorrupt)
	}
	recordSegments := make(map[string]publication.SnapshotSegment, len(snapshot.Segments))
	for _, segment := range snapshot.Segments {
		recordSegments[segment.Target.ID] = segment
	}
	segments := make([]AcceptedMaterialSegment, 0, len(owner.segments))
	for _, summary := range owner.segments {
		if err := s.checkContext(ctx, StageReadAcceptedMaterial); err != nil {
			return AcceptedMaterial{}, err
		}
		material := AcceptedMaterialSegment{Summary: summary}
		switch summary.Form {
		case PayloadFormPacked:
			name, nameErr := payloadBasenameFromCID(summary.BlobCID)
			if nameErr != nil || !validPayloadBasename(name) {
				return AcceptedMaterial{}, classified(ErrSchema, StageReadAcceptedMaterial, ReasonCorrupt)
			}
			blob := publication.BlobReference{
				CID:      bytes.Clone(summary.BlobCID),
				Size:     summary.BlobSize,
				MIMEType: publication.SnapshotBlobMIMEType,
			}
			data, readErr := s.inspectPayloadFile(name, nil, blob)
			if readErr != nil {
				return AcceptedMaterial{}, classifyAcceptedMaterialRead(readErr, StageReadAcceptedMaterial)
			}
			material.Blob = data
		case PayloadFormFileSet:
			entries, entryErr := s.readAcceptedSegmentEntries(ctx, summary, recordSegments[summary.TargetID])
			if entryErr != nil {
				return AcceptedMaterial{}, entryErr
			}
			material.Entries = entries
		case PayloadFormSettings:
		default:
			return AcceptedMaterial{}, classified(ErrSchema, StageReadAcceptedMaterial, ReasonCorrupt)
		}
		segments = append(segments, material)
	}
	return AcceptedMaterial{
		Floor:          cloneFloor(*state.floor),
		SnapshotRecord: bytes.Clone(owner.record),
		Segments:       segments,
	}, nil
}

func (s *Store) readAcceptedSegmentEntries(
	ctx context.Context,
	summary SegmentSummary,
	record publication.SnapshotSegment,
) ([]AcceptedMaterialEntry, error) {
	if len(record.Entries) != len(summary.Entries) {
		return nil, classified(ErrSchema, StageReadAcceptedMaterial, ReasonCorrupt)
	}
	contents := make(map[string][]byte, len(summary.Entries))
	entries := make([]AcceptedMaterialEntry, 0, len(summary.Entries))
	for index, reference := range summary.Entries {
		if err := s.checkContext(ctx, StageReadAcceptedMaterial); err != nil {
			return nil, err
		}
		entry := record.Entries[index]
		if entry.Path != reference.Path || entry.Size != reference.Size ||
			!bytes.Equal(entry.Blob.CID, reference.CID) {
			return nil, classified(ErrSchema, StageReadAcceptedMaterial, ReasonCorrupt)
		}
		key := string(reference.CID) + "\x00" + fmt.Sprint(reference.Size)
		content, present := contents[key]
		if !present {
			name, nameErr := payloadBasenameFromCID(reference.CID)
			if nameErr != nil || !validPayloadBasename(name) {
				return nil, classified(ErrSchema, StageReadAcceptedMaterial, ReasonCorrupt)
			}
			blob := publication.BlobReference{
				CID:      bytes.Clone(reference.CID),
				Size:     reference.Size,
				MIMEType: publication.SnapshotBlobMIMEType,
			}
			data, readErr := s.inspectCustodyObject(name, nil, blob, PayloadFormFileSet)
			if readErr != nil {
				return nil, classifyAcceptedMaterialRead(readErr, StageReadAcceptedMaterial)
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
		sameSegmentSummaries(left.Segments, right.Segments) &&
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
	if s.schemaVersion == 4 {
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
	var segmentsTypeValue, segmentsLengthValue, segmentsValue any
	var sequenceValue, revisionValue any
	var lifecycleValue, lifecycleLengthValue, outcomeValue, outcomeLengthValue, blockedValue, blockedLengthValue any
	var recordKeyValue, recordKeyLengthValue, recordSequenceValue any
	err := q.QueryRowContext(ctx, `SELECT
		substr(rp.attempt_id,1,17),length(rp.attempt_id),
		substr(rp.record_cid,1,129),length(rp.record_cid),
		typeof(rp.segments),length(CAST(rp.segments AS BLOB)),substr(CAST(rp.segments AS BLOB),1,2097153),
		rp.sequence,rp.accepted_revision,
		substr(pa.lifecycle,1,65),length(pa.lifecycle),substr(pa.outcome,1,65),length(pa.outcome),substr(pa.blocked,1,65),length(pa.blocked),
		substr(ar.record_key,1,17),length(ar.record_key),ar.sequence
		FROM retained_publications rp
		JOIN publication_attempts pa ON pa.attempt_id=rp.attempt_id
		JOIN accepted_events ae ON ae.revision=rp.accepted_revision
		JOIN accepted_records ar ON ar.cid=rp.record_cid
		WHERE rp.accepted_revision=?`, int64(floor.Revision)).Scan(
		&idValue, &idLengthValue, &recordValue, &recordLengthValue,
		&segmentsTypeValue, &segmentsLengthValue, &segmentsValue,
		&sequenceValue, &revisionValue,
		&lifecycleValue, &lifecycleLengthValue, &outcomeValue, &outcomeLengthValue, &blockedValue, &blockedLengthValue,
		&recordKeyValue, &recordKeyLengthValue, &recordSequenceValue)
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
	segmentsType, segmentsTypeOK := segmentsTypeValue.(string)
	segmentsLength, segmentsLengthOK := rawInt64(segmentsLengthValue)
	segmentsRaw, segmentsOK := rawBytes(segmentsValue)
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
	if !idOK || !idLengthOK || idLength != 16 || len(attemptID) != 16 ||
		!recordOK || !recordLengthOK || recordLength <= 0 || recordLength > publication.MaxCIDBytes || int64(len(recordCID)) != recordLength ||
		!segmentsTypeOK || segmentsType != "blob" || !segmentsLengthOK || segmentsLength < 1 ||
		segmentsLength > maxSegmentSummariesBytes || !segmentsOK || int64(len(segmentsRaw)) != segmentsLength ||
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
	segments, err := decodeSegmentSummaries(segmentsRaw)
	if err != nil || !sameSegmentSummaries(segments, floor.Segments) {
		return materialOwnership{}, classified(ErrSchema, stage, ReasonCorrupt)
	}
	cache := make(fileSetCatalogCache)
	for _, summary := range segments {
		if err := s.checkSegmentCatalog(ctx, q, summary, stage, cache); err != nil {
			return materialOwnership{}, err
		}
	}

	var id [16]byte
	copy(id[:], attemptID)
	attempt, err := s.loadStoredAttempt(ctx, q, id, stage)
	if err != nil {
		return materialOwnership{}, err
	}
	if attempt.lifecycle != AttemptRetiredSuccess || attempt.outcome != OutcomeCurrent || attempt.blocked != "" ||
		!bytes.Equal(attempt.core.SnapshotCID, floor.RecordCID) || attempt.core.SnapshotKey != floor.SnapshotKey {
		return materialOwnership{}, classified(ErrSchema, stage, ReasonCorrupt)
	}

	record, err := s.loadRecordByCID(ctx, q, floor.RecordCID, floor.SnapshotKey, floor.Sequence, stage)
	if err != nil {
		return materialOwnership{}, err
	}
	snapshot, err := publication.DecodeSnapshot(record.raw)
	if err != nil || snapshot.Vault != floor.Binding.Vault || snapshot.PublicationSeq != floor.Sequence ||
		snapshot.PublicationID != floor.PublicationID ||
		!bytes.Equal(attempt.core.SnapshotRecord, record.raw) {
		return materialOwnership{}, classified(ErrSchema, stage, ReasonCorrupt)
	}
	return materialOwnership{segments: segments, record: bytes.Clone(record.raw)}, nil
}

func (s *Store) incomingAcceptedMaterialOwner(
	ctx context.Context,
	q queryer,
	floor Floor,
	stage Stage,
) (materialOwnership, error) {
	var revisionTypeValue, revisionValue, recordTypeValue, recordLengthValue, recordValue any
	var segmentsTypeValue, segmentsLengthValue, segmentsValue any
	err := q.QueryRowContext(ctx, "SELECT typeof(accepted_revision),CASE WHEN typeof(accepted_revision)='integer' THEN accepted_revision END,typeof(record_cid),length(CAST(record_cid AS BLOB)),substr(CAST(record_cid AS BLOB),1,129),typeof(segments),length(CAST(segments AS BLOB)),substr(CAST(segments AS BLOB),1,2097153) FROM accepted_material_refs WHERE accepted_revision=?", int64(floor.Revision)).
		Scan(
			&revisionTypeValue, &revisionValue, &recordTypeValue, &recordLengthValue, &recordValue,
			&segmentsTypeValue, &segmentsLengthValue, &segmentsValue)
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
	segmentsType, segmentsTypeOK := segmentsTypeValue.(string)
	segmentsLength, segmentsLengthOK := rawInt64(segmentsLengthValue)
	segmentsRaw, segmentsOK := rawBytes(segmentsValue)
	if !revisionTypeOK || revisionType != "integer" || !revisionOK || revision < 1 ||
		uint64(revision) != floor.Revision ||
		!recordTypeOK || recordType != "blob" || !recordLengthOK || recordLength < 1 ||
		recordLength > publication.MaxCIDBytes || !recordOK ||
		int64(len(recordCID)) != recordLength ||
		!segmentsTypeOK || segmentsType != "blob" || !segmentsLengthOK || segmentsLength < 1 ||
		segmentsLength > maxSegmentSummariesBytes || !segmentsOK || int64(len(segmentsRaw)) != segmentsLength ||
		!bytes.Equal(recordCID, floor.RecordCID) {
		return materialOwnership{}, classified(ErrSchema, stage, ReasonCorrupt)
	}
	segments, err := decodeSegmentSummaries(segmentsRaw)
	if err != nil || !sameSegmentSummaries(segments, floor.Segments) {
		return materialOwnership{}, classified(ErrSchema, stage, ReasonCorrupt)
	}
	cache := make(fileSetCatalogCache)
	for _, summary := range segments {
		if err := s.checkSegmentCatalog(ctx, q, summary, stage, cache); err != nil {
			return materialOwnership{}, err
		}
	}
	record, err := s.loadRecordByCID(ctx, q, floor.RecordCID, floor.SnapshotKey, floor.Sequence, stage)
	if err != nil {
		return materialOwnership{}, err
	}
	snapshot, err := publication.DecodeSnapshot(record.raw)
	if err != nil || !sameSegmentSummaries(summariesOfRecord(snapshot.Segments), segments) {
		return materialOwnership{}, classified(ErrSchema, stage, ReasonCorrupt)
	}
	return materialOwnership{segments: segments, record: bytes.Clone(record.raw)}, nil
}

func (s *Store) checkSegmentCatalog(
	ctx context.Context,
	q queryer,
	summary SegmentSummary,
	stage Stage,
	cache fileSetCatalogCache,
) error {
	switch summary.Form {
	case PayloadFormPacked:
		object, err := s.readPayloadCatalogRow(ctx, q, summary.BlobCID, stage)
		if err != nil {
			return err
		}
		if object.size != int64(summary.BlobSize) || !bytes.Equal(object.cid, summary.BlobCID) {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
		wantedName, nameErr := payloadBasenameFromCID(summary.BlobCID)
		if nameErr != nil || !validPayloadBasename(object.name) || object.name != wantedName {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
		return nil
	case PayloadFormFileSet:
		return s.checkIncomingFileSetCatalog(ctx, q, summary.Entries, stage, cache)
	case PayloadFormSettings:
		return nil
	default:
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
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

func sameSegmentSummaries(left, right []SegmentSummary) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].TargetID != right[index].TargetID || left[index].Form != right[index].Form ||
			!bytes.Equal(left[index].BlobCID, right[index].BlobCID) ||
			left[index].BlobSize != right[index].BlobSize ||
			left[index].Settings != right[index].Settings ||
			len(left[index].Entries) != len(right[index].Entries) {
			return false
		}
		for entry := range left[index].Entries {
			if left[index].Entries[entry].Path != right[index].Entries[entry].Path ||
				left[index].Entries[entry].Size != right[index].Entries[entry].Size ||
				!bytes.Equal(left[index].Entries[entry].CID, right[index].Entries[entry].CID) {
				return false
			}
		}
	}
	return true
}
