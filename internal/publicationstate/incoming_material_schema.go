package publicationstate

import (
	"bytes"
	"context"
	"database/sql"
	"errors"

	"github.com/lamb-systems/dottie/internal/publication"
)

const incomingMaterialSchemaStatement = "CREATE TABLE accepted_material_refs (accepted_revision INTEGER PRIMARY KEY NOT NULL REFERENCES accepted_events(revision), record_cid BLOB NOT NULL REFERENCES accepted_records(cid), blob_cid BLOB NOT NULL REFERENCES payload_objects(blob_cid))"

type incomingMaterialRef struct {
	revision  int64
	recordCID []byte
	blobCID   []byte
}

func (s *Store) checkIncomingMaterialRefs(ctx context.Context, q queryer, stage Stage) error {
	if ctx == nil {
		return classified(ErrInvalid, stage, ReasonContext)
	}
	if err := s.checkContext(ctx, stage); err != nil {
		return err
	}
	var eventCountValue, refCountValue any
	if err := q.QueryRowContext(ctx, "SELECT (SELECT COUNT(*) FROM accepted_events),(SELECT COUNT(*) FROM accepted_material_refs)").Scan(&eventCountValue, &refCountValue); err != nil {
		return storageFailure(ctx, stage, err)
	}
	eventCount, eventCountOK := rawInt64(eventCountValue)
	refCount, refCountOK := rawInt64(refCountValue)
	if !eventCountOK || !refCountOK || eventCount < 0 || refCount < 0 || refCount > eventCount || uint64(eventCount) > uint64(s.limits.AcceptedEventCount) {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	rows, err := q.QueryContext(ctx, "SELECT typeof(accepted_revision),CASE WHEN typeof(accepted_revision)='integer' THEN accepted_revision END,typeof(record_cid),length(CAST(record_cid AS BLOB)),substr(CAST(record_cid AS BLOB),1,129),typeof(blob_cid),length(CAST(blob_cid AS BLOB)),substr(CAST(blob_cid AS BLOB),1,129) FROM accepted_material_refs ORDER BY accepted_revision LIMIT ?", int64(s.limits.AcceptedEventCount)+1)
	if err != nil {
		return storageFailure(ctx, stage, err)
	}
	refs := make([]incomingMaterialRef, 0, int(refCount))
	closed := false
	defer func() {
		if !closed {
			_ = rows.Close()
		}
	}()
	for rows.Next() {
		values, scanErr := scanRawValues(rows, 8)
		if scanErr != nil {
			return storageFailure(ctx, stage, scanErr)
		}
		revisionType, revisionTypeOK := values[0].(string)
		revision, revisionOK := rawInt64(values[1])
		recordType, recordTypeOK := values[2].(string)
		recordLength, recordLengthOK := rawInt64(values[3])
		recordCID, recordCIDOK := rawBytes(values[4])
		blobType, blobTypeOK := values[5].(string)
		blobLength, blobLengthOK := rawInt64(values[6])
		blobCID, blobCIDOK := rawBytes(values[7])
		if !revisionTypeOK || revisionType != "integer" || !revisionOK || revision < 1 || uint64(revision) > publication.MaxSequence {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
		if !recordTypeOK || recordType != "blob" || !recordLengthOK || recordLength < 1 || recordLength > publication.MaxCIDBytes || !recordCIDOK || int64(len(recordCID)) != recordLength {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
		if !blobTypeOK || blobType != "blob" || !blobLengthOK || blobLength < 1 || blobLength > publication.MaxCIDBytes || !blobCIDOK || int64(len(blobCID)) != blobLength {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
		if len(refs) >= int(refCount) || len(refs) >= int(s.limits.AcceptedEventCount) {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
		refs = append(refs, incomingMaterialRef{revision: revision, recordCID: bytes.Clone(recordCID), blobCID: bytes.Clone(blobCID)})
	}
	if err := rows.Err(); err != nil {
		return storageFailure(ctx, stage, err)
	}
	if err := rows.Close(); err != nil {
		return storageFailure(ctx, stage, err)
	}
	closed = true
	if len(refs) != int(refCount) {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	for _, ref := range refs {
		if err := s.checkIncomingMaterialRef(ctx, q, ref, stage); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) checkIncomingMaterialRef(ctx context.Context, q queryer, ref incomingMaterialRef, stage Stage) error {
	retainedCount, err := queryInt64(ctx, q, "SELECT COUNT(*) FROM retained_publications WHERE accepted_revision=?", ref.revision)
	if err != nil {
		return queryReadError(ctx, stage, err)
	}
	if retainedCount != 0 {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	var floorTypeValue, floorLengthValue, floorValue, digestTypeValue, digestLengthValue, digestValue any
	err = q.QueryRowContext(ctx, "SELECT typeof(new_floor),length(CAST(new_floor AS BLOB)),substr(CAST(new_floor AS BLOB),1,65537),typeof(digest),length(CAST(digest AS BLOB)),substr(CAST(digest AS BLOB),1,33) FROM accepted_events WHERE revision=?", ref.revision).Scan(&floorTypeValue, &floorLengthValue, &floorValue, &digestTypeValue, &digestLengthValue, &digestValue)
	if errors.Is(err, sql.ErrNoRows) {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	if err != nil {
		return storageFailure(ctx, stage, err)
	}
	floorType, floorTypeOK := floorTypeValue.(string)
	floorLength, floorLengthOK := rawInt64(floorLengthValue)
	floorRaw, floorOK := rawBytes(floorValue)
	digestType, digestTypeOK := digestTypeValue.(string)
	digestLength, digestLengthOK := rawInt64(digestLengthValue)
	digestRaw, digestOK := rawBytes(digestValue)
	if !floorTypeOK || floorType != "blob" || !floorLengthOK || floorLength < 1 || floorLength > 65536 || !floorOK || int64(len(floorRaw)) != floorLength {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	if !digestTypeOK || digestType != "blob" || !digestLengthOK || digestLength != 32 || !digestOK || int64(len(digestRaw)) != digestLength {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	floor, err := decodeFloor(floorRaw)
	if err != nil || validatePersistedFloor(floor, s.binding, s.databaseID, s.limits) != nil {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	if floor.Revision != uint64(ref.revision) || !bytes.Equal(floor.RecordCID, ref.recordCID) || !bytes.Equal(floor.BlobCID, ref.blobCID) || !bytes.Equal(floor.AcceptedEventDigest[:], digestRaw) {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	var cidTypeValue, cidLengthValue, cidValue, keyTypeValue, keyLengthValue, keyValue, sequenceTypeValue, sequenceValue, rawTypeValue, rawLengthValue, rawValue, logicalTypeValue, logicalValue any
	err = q.QueryRowContext(ctx, "SELECT typeof(cid),length(CAST(cid AS BLOB)),substr(CAST(cid AS BLOB),1,129),typeof(record_key),length(CAST(record_key AS BLOB)),substr(CAST(record_key AS BLOB),1,17),typeof(sequence),CASE WHEN typeof(sequence)='integer' THEN sequence END,typeof(raw),length(CAST(raw AS BLOB)),substr(CAST(raw AS BLOB),1,2049),typeof(logical_bytes),CASE WHEN typeof(logical_bytes)='integer' THEN logical_bytes END FROM accepted_records WHERE cid=?", ref.recordCID).Scan(&cidTypeValue, &cidLengthValue, &cidValue, &keyTypeValue, &keyLengthValue, &keyValue, &sequenceTypeValue, &sequenceValue, &rawTypeValue, &rawLengthValue, &rawValue, &logicalTypeValue, &logicalValue)
	if errors.Is(err, sql.ErrNoRows) {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	if err != nil {
		return storageFailure(ctx, stage, err)
	}
	cidType, cidTypeOK := cidTypeValue.(string)
	cidLength, cidLengthOK := rawInt64(cidLengthValue)
	cid, cidOK := rawBytes(cidValue)
	keyType, keyTypeOK := keyTypeValue.(string)
	keyLength, keyLengthOK := rawInt64(keyLengthValue)
	keyBytes, keyOK := rawBytes(keyValue)
	sequenceType, sequenceTypeOK := sequenceTypeValue.(string)
	sequence, sequenceOK := rawInt64(sequenceValue)
	recordRawType, recordRawTypeOK := rawTypeValue.(string)
	recordRawLength, recordRawLengthOK := rawInt64(rawLengthValue)
	recordRaw, recordRawOK := rawBytes(rawValue)
	logicalType, logicalTypeOK := logicalTypeValue.(string)
	logical, logicalOK := rawInt64(logicalValue)
	if !cidTypeOK || cidType != "blob" || !cidLengthOK || cidLength < 1 || cidLength > publication.MaxCIDBytes || !cidOK || int64(len(cid)) != cidLength {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	if !keyTypeOK || keyType != "text" || !keyLengthOK || keyLength != publication.SequenceKeyLength || !keyOK || int64(len(keyBytes)) != keyLength {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	if !sequenceTypeOK || sequenceType != "integer" || !sequenceOK || sequence < 0 || uint64(sequence) > publication.MaxSequence {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	if !recordRawTypeOK || recordRawType != "blob" || !recordRawLengthOK || recordRawLength < 1 || recordRawLength > publication.MaxRecordBytes || !recordRawOK || int64(len(recordRaw)) != recordRawLength {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	if !logicalTypeOK || logicalType != "integer" || !logicalOK || logical < 0 {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	stored := rawStoredRecord{key: string(keyBytes), sequence: uint64(sequence), cid: bytes.Clone(cid), raw: bytes.Clone(recordRaw)}
	record, err := s.verifyStoredRecord(stored, stage)
	if err != nil || recordLogicalBytes(record) != uint64(logical) || !bytes.Equal(record.ref.CID, ref.recordCID) || record.ref.Key != floor.SnapshotKey || record.ref.Sequence != floor.Sequence {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	snapshot, err := publication.DecodeSnapshot(record.raw)
	if err != nil || snapshot.Vault != floor.Binding.Vault || snapshot.PublicationSeq != floor.Sequence || snapshot.PublicationID != floor.PublicationID || !bytes.Equal(snapshot.Blob.CID, floor.BlobCID) || snapshot.Blob.Size != floor.BlobSize {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	if publication.VerifyHeadBinding(floor.Head, record.raw, floor.SnapshotKey) != nil {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	var catalogCIDTypeValue, catalogCIDLengthValue, catalogCIDValue, sizeTypeValue, sizeValue, nameTypeValue, nameLengthValue, nameValue, catalogLogicalTypeValue, catalogLogicalValue any
	err = q.QueryRowContext(ctx, "SELECT typeof(blob_cid),length(CAST(blob_cid AS BLOB)),substr(CAST(blob_cid AS BLOB),1,129),typeof(size),CASE WHEN typeof(size)='integer' THEN size END,typeof(basename),length(CAST(basename AS BLOB)),substr(CAST(basename AS BLOB),1,73),typeof(logical_bytes),CASE WHEN typeof(logical_bytes)='integer' THEN logical_bytes END FROM payload_objects WHERE blob_cid=?", ref.blobCID).Scan(&catalogCIDTypeValue, &catalogCIDLengthValue, &catalogCIDValue, &sizeTypeValue, &sizeValue, &nameTypeValue, &nameLengthValue, &nameValue, &catalogLogicalTypeValue, &catalogLogicalValue)
	if errors.Is(err, sql.ErrNoRows) {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	if err != nil {
		return storageFailure(ctx, stage, err)
	}
	catalogCIDType, catalogCIDTypeOK := catalogCIDTypeValue.(string)
	catalogCIDLength, catalogCIDLengthOK := rawInt64(catalogCIDLengthValue)
	catalogCID, catalogCIDOK := rawBytes(catalogCIDValue)
	sizeType, sizeTypeOK := sizeTypeValue.(string)
	size, sizeOK := rawInt64(sizeValue)
	nameType, nameTypeOK := nameTypeValue.(string)
	nameLength, nameLengthOK := rawInt64(nameLengthValue)
	nameBytes, nameOK := rawBytes(nameValue)
	catalogLogicalType, catalogLogicalTypeOK := catalogLogicalTypeValue.(string)
	catalogLogical, catalogLogicalOK := rawInt64(catalogLogicalValue)
	if !catalogCIDTypeOK || catalogCIDType != "blob" || !catalogCIDLengthOK || catalogCIDLength < 1 || catalogCIDLength > publication.MaxCIDBytes || !catalogCIDOK || int64(len(catalogCID)) != catalogCIDLength {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	if !sizeTypeOK || sizeType != "integer" || !sizeOK || size <= 0 || uint64(size) > publication.MaxBlobBytes {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	if !nameTypeOK || nameType != "text" || !nameLengthOK || nameLength != int64(64+len(payloadSuffix)) || !nameOK || int64(len(nameBytes)) != nameLength {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	if !catalogLogicalTypeOK || catalogLogicalType != "integer" || !catalogLogicalOK || catalogLogical < 0 || catalogLogical != size {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	if !bytes.Equal(catalogCID, ref.blobCID) || !bytes.Equal(ref.blobCID, floor.BlobCID) || uint64(size) != floor.BlobSize {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	name := string(nameBytes)
	wantedName, nameErr := payloadBasenameFromCID(ref.blobCID)
	if nameErr != nil || !validPayloadBasename(name) || name != wantedName {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	return nil
}
