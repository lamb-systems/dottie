package publication

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/ipfs/go-cid"
)

const maxRecordJSONBytes = 8192

var ErrRecordJSON = errors.New("publication record JSON conversion failed")

func RecordToJSON(canonicalRecord []byte) ([]byte, error) {
	return recordToJSONWithEncoder(canonicalRecord, json.Marshal)
}

func recordToJSONWithEncoder(canonicalRecord []byte, encode func(any) ([]byte, error)) ([]byte, error) {
	expectedCID, err := RecordCID(canonicalRecord)
	if err != nil {
		return nil, err
	}

	value, err := recordJSONValue(canonicalRecord)
	if err != nil {
		return nil, recordJSONViolation("encoding")
	}
	if encode == nil {
		return nil, recordJSONViolation("encoding")
	}
	encoded, err := encode(value)
	if err != nil {
		return nil, recordJSONViolation("encoding")
	}
	if len(encoded) > maxRecordJSONBytes {
		return nil, recordJSONViolation("size_limit")
	}

	parsed, err := atdata.UnmarshalJSON(encoded)
	if err != nil {
		return nil, recordJSONViolation("reconstruction")
	}
	reconstructed, err := atdata.MarshalCBOR(parsed)
	if err != nil {
		return nil, recordJSONViolation("reconstruction")
	}
	reconstructedCID, err := RecordCID(reconstructed)
	if err != nil {
		return nil, recordJSONViolation("reconstruction")
	}
	if !bytes.Equal(expectedCID, reconstructedCID) {
		return nil, recordJSONViolation("cid_mismatch")
	}
	if !bytes.Equal(canonicalRecord, reconstructed) {
		return nil, recordJSONViolation("byte_mismatch")
	}
	return bytes.Clone(encoded), nil
}

func recordJSONValue(canonicalRecord []byte) (map[string]any, error) {
	object, err := decodeObject(canonicalRecord)
	if err != nil {
		return nil, err
	}
	typeID, ok := object["$type"].(string)
	if !ok {
		return nil, ErrInvalidRecord
	}
	switch typeID {
	case SnapshotNSID:
		record, err := DecodeSnapshot(canonicalRecord)
		if err != nil {
			return nil, err
		}
		blobCID, err := cid.Cast(record.Blob.CID)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"$type":          SnapshotNSID,
			"schemaVersion":  record.SchemaVersion,
			"vault":          atdata.Bytes(cloneRecordBytes(record.Vault[:])),
			"publicationId":  atdata.Bytes(cloneRecordBytes(record.PublicationID[:])),
			"publicationSeq": int64(record.PublicationSeq),
			"parent":         atdata.Bytes(cloneRecordBytes(record.Parent)),
			"blob": atdata.Blob{
				Ref:      atdata.CIDLink(blobCID),
				MimeType: BlobMIMEType,
				Size:     int64(record.Blob.Size),
			},
		}, nil
	case HeadNSID:
		record, err := DecodeHead(canonicalRecord)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"$type":          HeadNSID,
			"schemaVersion":  record.SchemaVersion,
			"vault":          atdata.Bytes(cloneRecordBytes(record.Vault[:])),
			"publicationSeq": int64(record.PublicationSeq),
			"snapshotCid":    atdata.Bytes(cloneRecordBytes(record.SnapshotCID)),
			"blobCid":        atdata.Bytes(cloneRecordBytes(record.BlobCID)),
		}, nil
	default:
		return nil, ErrInvalidRecord
	}
}

func cloneRecordBytes(value []byte) []byte {
	cloned := make([]byte, len(value))
	copy(cloned, value)
	return cloned
}

func recordJSONViolation(reason string) error {
	return violation(ErrRecordJSON, "record", reason)
}
