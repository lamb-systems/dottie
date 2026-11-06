package publication

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"unicode/utf8"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
)

const (
	SnapshotNSID      = "systems.lamb.dottie.vaultSnapshotV2"
	HeadNSID          = "systems.lamb.dottie.vaultHeadV2"
	SchemaVersion     = int64(2)
	MaxSequence       = uint64(9007199254740991)
	MaxRecordBytes    = 2048
	MaxCIDBytes       = 128
	MaxBlobBytes      = uint64(402653184)
	BlobMIMEType      = "application/octet-stream"
	SequenceKeyLength = 16
)

var (
	ErrInvalidRecord = errors.New("invalid publication record")
	ErrNonCanonical  = errors.New("noncanonical publication record")
	ErrSequenceKey   = errors.New("invalid publication sequence key")
	ErrCID           = errors.New("invalid publication CID")
	ErrBinding       = errors.New("publication binding mismatch")
	ErrPayload       = errors.New("publication payload mismatch")
)

type Violation struct {
	cause  error
	field  string
	reason string
}

func (e *Violation) Error() string {
	return fmt.Sprintf("publication: %s: %s: %s", e.cause.Error(), e.field, e.reason)
}

func (e *Violation) Unwrap() error { return e.cause }

func (e *Violation) Field() string { return e.field }

func (e *Violation) Reason() string { return e.reason }

type BlobReference struct {
	CID  []byte
	Size uint64
}

type SnapshotRecord struct {
	SchemaVersion  int64
	Vault          [32]byte
	PublicationID  [16]byte
	PublicationSeq uint64
	Parent         []byte
	Blob           BlobReference
}

type HeadRecord struct {
	SchemaVersion  int64
	Vault          [32]byte
	PublicationSeq uint64
	SnapshotCID    []byte
	BlobCID        []byte
}

func SequenceKey(sequence uint64) (string, error) {
	if sequence > MaxSequence {
		return "", violation(ErrSequenceKey, "sequence", "out_of_range")
	}
	return fmt.Sprintf("%0*d", SequenceKeyLength, sequence), nil
}

func ParseSequenceKey(key string) (uint64, error) {
	if len(key) != SequenceKeyLength {
		return 0, violation(ErrSequenceKey, "snapshotKey", "format")
	}
	for index := 0; index < len(key); index++ {
		if key[index] < '0' || key[index] > '9' {
			return 0, violation(ErrSequenceKey, "snapshotKey", "format")
		}
	}
	sequence, err := strconv.ParseUint(key, 10, 64)
	if err != nil || sequence > MaxSequence {
		return 0, violation(ErrSequenceKey, "snapshotKey", "out_of_range")
	}
	return sequence, nil
}

func EncodeSnapshot(record SnapshotRecord) ([]byte, error) {
	if err := validateSnapshot(record); err != nil {
		return nil, err
	}
	parent := bytes.Clone(record.Parent)
	if parent == nil {
		parent = []byte{}
	}
	blobCID, err := castCID(record.Blob.CID, cid.Raw, "blob.ref")
	if err != nil {
		return nil, err
	}
	object := map[string]any{
		"$type":          SnapshotNSID,
		"schemaVersion":  SchemaVersion,
		"vault":          bytes.Clone(record.Vault[:]),
		"publicationId":  bytes.Clone(record.PublicationID[:]),
		"publicationSeq": int64(record.PublicationSeq),
		"parent":         parent,
		"blob": atdata.Blob{
			Ref:      atdata.CIDLink(blobCID),
			MimeType: BlobMIMEType,
			Size:     int64(record.Blob.Size),
		},
	}
	encoded, err := atdata.MarshalCBOR(object)
	if err != nil {
		return nil, violation(ErrInvalidRecord, "record", "encode")
	}
	if len(encoded) > MaxRecordBytes {
		return nil, violation(ErrInvalidRecord, "record", "size_limit")
	}
	return encoded, nil
}

func DecodeSnapshot(encoded []byte) (SnapshotRecord, error) {
	object, err := decodeObject(encoded)
	if err != nil {
		return SnapshotRecord{}, err
	}
	if err := exactKeys(object, "$type", "schemaVersion", "vault", "publicationId", "publicationSeq", "parent", "blob"); err != nil {
		return SnapshotRecord{}, err
	}
	if object["$type"] != SnapshotNSID {
		return SnapshotRecord{}, violation(ErrInvalidRecord, "$type", "unsupported")
	}
	version, ok := integer(object["schemaVersion"])
	if !ok || version != SchemaVersion {
		return SnapshotRecord{}, violation(ErrInvalidRecord, "schemaVersion", "unsupported")
	}
	vaultBytes, ok := byteString(object["vault"])
	if !ok || len(vaultBytes) != 32 {
		return SnapshotRecord{}, violation(ErrInvalidRecord, "vault", "length")
	}
	publicationBytes, ok := byteString(object["publicationId"])
	if !ok || len(publicationBytes) != 16 {
		return SnapshotRecord{}, violation(ErrInvalidRecord, "publicationId", "length")
	}
	sequence, ok := unsignedInteger(object["publicationSeq"])
	if !ok {
		return SnapshotRecord{}, violation(ErrInvalidRecord, "publicationSeq", "integer")
	}
	parent, ok := byteString(object["parent"])
	if !ok || len(parent) > MaxCIDBytes {
		return SnapshotRecord{}, violation(ErrInvalidRecord, "parent", "length")
	}
	blob, ok := object["blob"].(atdata.Blob)
	if !ok {
		return SnapshotRecord{}, violation(ErrInvalidRecord, "blob", "type")
	}
	if blob.MimeType != BlobMIMEType {
		return SnapshotRecord{}, violation(ErrInvalidRecord, "blob.mimeType", "unsupported")
	}
	if blob.Size <= 0 || uint64(blob.Size) > MaxBlobBytes {
		return SnapshotRecord{}, violation(ErrInvalidRecord, "blob.size", "range")
	}
	blobCID, err := validateCID([]byte(blob.Ref.CID().Bytes()), cid.Raw, "blob.ref")
	if err != nil {
		return SnapshotRecord{}, err
	}
	var record SnapshotRecord
	record.SchemaVersion = version
	copy(record.Vault[:], vaultBytes)
	copy(record.PublicationID[:], publicationBytes)
	record.PublicationSeq = sequence
	record.Parent = bytes.Clone(parent)
	record.Blob = BlobReference{CID: blobCID.Bytes(), Size: uint64(blob.Size)}
	if err := validateSnapshot(record); err != nil {
		return SnapshotRecord{}, err
	}
	canonical, err := EncodeSnapshot(record)
	if err != nil {
		return SnapshotRecord{}, err
	}
	if !bytes.Equal(encoded, canonical) {
		return SnapshotRecord{}, violation(ErrNonCanonical, "record", "byte_mismatch")
	}
	return record, nil
}

func EncodeHead(record HeadRecord) ([]byte, error) {
	if err := validateHead(record); err != nil {
		return nil, err
	}
	snapshotCID, err := castCID(record.SnapshotCID, cid.DagCBOR, "snapshotCid")
	if err != nil {
		return nil, err
	}
	blobCID, err := castCID(record.BlobCID, cid.Raw, "blobCid")
	if err != nil {
		return nil, err
	}
	encoded, err := atdata.MarshalCBOR(map[string]any{
		"$type":          HeadNSID,
		"schemaVersion":  SchemaVersion,
		"vault":          bytes.Clone(record.Vault[:]),
		"publicationSeq": int64(record.PublicationSeq),
		"snapshotCid":    snapshotCID.Bytes(),
		"blobCid":        blobCID.Bytes(),
	})
	if err != nil {
		return nil, violation(ErrInvalidRecord, "record", "encode")
	}
	if len(encoded) > MaxRecordBytes {
		return nil, violation(ErrInvalidRecord, "record", "size_limit")
	}
	return encoded, nil
}

func DecodeHead(encoded []byte) (HeadRecord, error) {
	object, err := decodeObject(encoded)
	if err != nil {
		return HeadRecord{}, err
	}
	if err := exactKeys(object, "$type", "schemaVersion", "vault", "publicationSeq", "snapshotCid", "blobCid"); err != nil {
		return HeadRecord{}, err
	}
	if object["$type"] != HeadNSID {
		return HeadRecord{}, violation(ErrInvalidRecord, "$type", "unsupported")
	}
	version, ok := integer(object["schemaVersion"])
	if !ok || version != SchemaVersion {
		return HeadRecord{}, violation(ErrInvalidRecord, "schemaVersion", "unsupported")
	}
	vaultBytes, ok := byteString(object["vault"])
	if !ok || len(vaultBytes) != 32 {
		return HeadRecord{}, violation(ErrInvalidRecord, "vault", "length")
	}
	sequence, ok := unsignedInteger(object["publicationSeq"])
	if !ok {
		return HeadRecord{}, violation(ErrInvalidRecord, "publicationSeq", "integer")
	}
	snapshotBytes, ok := byteString(object["snapshotCid"])
	if !ok {
		return HeadRecord{}, violation(ErrInvalidRecord, "snapshotCid", "type")
	}
	if len(snapshotBytes) == 0 || len(snapshotBytes) > MaxCIDBytes {
		return HeadRecord{}, violation(ErrCID, "snapshotCid", "length")
	}
	blobBytes, ok := byteString(object["blobCid"])
	if !ok {
		return HeadRecord{}, violation(ErrInvalidRecord, "blobCid", "type")
	}
	if len(blobBytes) == 0 || len(blobBytes) > MaxCIDBytes {
		return HeadRecord{}, violation(ErrCID, "blobCid", "length")
	}
	var record HeadRecord
	record.SchemaVersion = version
	copy(record.Vault[:], vaultBytes)
	record.PublicationSeq = sequence
	record.SnapshotCID = bytes.Clone(snapshotBytes)
	record.BlobCID = bytes.Clone(blobBytes)
	if err := validateHead(record); err != nil {
		return HeadRecord{}, err
	}
	canonical, err := EncodeHead(record)
	if err != nil {
		return HeadRecord{}, err
	}
	if !bytes.Equal(encoded, canonical) {
		return HeadRecord{}, violation(ErrNonCanonical, "record", "byte_mismatch")
	}
	return record, nil
}

func RecordCID(encoded []byte) ([]byte, error) {
	object, err := decodeObject(encoded)
	if err != nil {
		return nil, err
	}
	typeID, ok := object["$type"].(string)
	if !ok {
		return nil, violation(ErrInvalidRecord, "$type", "invalid")
	}
	switch typeID {
	case SnapshotNSID:
		if _, err := DecodeSnapshot(encoded); err != nil {
			return nil, err
		}
	case HeadNSID:
		if _, err := DecodeHead(encoded); err != nil {
			return nil, err
		}
	default:
		return nil, violation(ErrInvalidRecord, "$type", "unsupported")
	}
	hash, err := multihash.Sum(encoded, multihash.SHA2_256, 32)
	if err != nil {
		return nil, violation(ErrCID, "record", "hash")
	}
	return cid.NewCidV1(cid.DagCBOR, hash).Bytes(), nil
}

func RawPayloadCID(payload []byte) ([]byte, error) {
	if len(payload) == 0 || uint64(len(payload)) > MaxBlobBytes {
		return nil, violation(ErrPayload, "payload.size", "range")
	}
	hash, err := multihash.Sum(payload, multihash.SHA2_256, 32)
	if err != nil {
		return nil, violation(ErrCID, "payload", "hash")
	}
	return cid.NewCidV1(cid.Raw, hash).Bytes(), nil
}

func VerifyPayload(payload []byte, blob BlobReference) error {
	if blob.Size != uint64(len(payload)) {
		return violation(ErrPayload, "blob.size", "mismatch")
	}
	if blob.Size == 0 || blob.Size > MaxBlobBytes {
		return violation(ErrPayload, "blob.size", "range")
	}
	wanted, err := RawPayloadCID(payload)
	if err != nil {
		return err
	}
	if len(blob.CID) != len(wanted) || !bytes.Equal(blob.CID, wanted) {
		return violation(ErrPayload, "blob.ref", "mismatch")
	}
	return nil
}

func VerifyHeadBinding(headEncoded, snapshotEncoded []byte, snapshotKey string) error {
	head, err := DecodeHead(headEncoded)
	if err != nil {
		return err
	}
	snapshot, err := DecodeSnapshot(snapshotEncoded)
	if err != nil {
		return err
	}
	keySequence, err := ParseSequenceKey(snapshotKey)
	if err != nil {
		return err
	}
	if keySequence != snapshot.PublicationSeq {
		return violation(ErrBinding, "snapshotKey", "sequence_mismatch")
	}
	if !bytes.Equal(head.Vault[:], snapshot.Vault[:]) {
		return violation(ErrBinding, "vault", "mismatch")
	}
	if head.PublicationSeq != snapshot.PublicationSeq {
		return violation(ErrBinding, "publicationSeq", "mismatch")
	}
	recordCID, err := RecordCID(snapshotEncoded)
	if err != nil {
		return err
	}
	if !bytes.Equal(head.SnapshotCID, recordCID) {
		return violation(ErrBinding, "snapshotCid", "mismatch")
	}
	if !bytes.Equal(head.BlobCID, snapshot.Blob.CID) {
		return violation(ErrBinding, "blobCid", "mismatch")
	}
	return nil
}

func VerifySuccessor(previousEncoded, successorEncoded []byte, successorKey string) error {
	previous, err := DecodeSnapshot(previousEncoded)
	if err != nil {
		return err
	}
	successor, err := DecodeSnapshot(successorEncoded)
	if err != nil {
		return err
	}
	keySequence, err := ParseSequenceKey(successorKey)
	if err != nil {
		return err
	}
	if keySequence != successor.PublicationSeq {
		return violation(ErrBinding, "snapshotKey", "sequence_mismatch")
	}
	if !bytes.Equal(previous.Vault[:], successor.Vault[:]) {
		return violation(ErrBinding, "vault", "mismatch")
	}
	if previous.PublicationSeq == MaxSequence || successor.PublicationSeq != previous.PublicationSeq+1 {
		return violation(ErrBinding, "publicationSeq", "not_successor")
	}
	previousCID, err := RecordCID(previousEncoded)
	if err != nil {
		return err
	}
	if !bytes.Equal(successor.Parent, previousCID) {
		return violation(ErrBinding, "parent", "mismatch")
	}
	return nil
}

func decodeObject(encoded []byte) (map[string]any, error) {
	if len(encoded) == 0 || len(encoded) > MaxRecordBytes {
		return nil, violation(ErrInvalidRecord, "record", "size_limit")
	}
	object, err := atdata.UnmarshalCBOR(encoded)
	if err != nil {
		return nil, violation(ErrInvalidRecord, "record", "invalid_cbor")
	}
	if !validUTF8(object) {
		return nil, violation(ErrNonCanonical, "record", "invalid_utf8")
	}
	return object, nil
}

func validUTF8(value any) bool {
	switch item := value.(type) {
	case string:
		return utf8.ValidString(item)
	case atdata.Blob:
		return utf8.ValidString(item.MimeType)
	case map[string]any:
		for key, nested := range item {
			if !utf8.ValidString(key) || !validUTF8(nested) {
				return false
			}
		}
	case []any:
		for _, nested := range item {
			if !validUTF8(nested) {
				return false
			}
		}
	}
	return true
}

func exactKeys(object map[string]any, names ...string) error {
	if len(object) != len(names) {
		return violation(ErrInvalidRecord, "record", "fields")
	}
	for _, name := range names {
		if _, ok := object[name]; !ok {
			return violation(ErrInvalidRecord, name, "missing")
		}
	}
	return nil
}

func validateSnapshot(record SnapshotRecord) error {
	if record.SchemaVersion != SchemaVersion {
		return violation(ErrInvalidRecord, "schemaVersion", "unsupported")
	}
	if allZero(record.Vault[:]) {
		return violation(ErrInvalidRecord, "vault", "zero")
	}
	if allZero(record.PublicationID[:]) {
		return violation(ErrInvalidRecord, "publicationId", "zero")
	}
	if record.PublicationSeq > MaxSequence {
		return violation(ErrInvalidRecord, "publicationSeq", "range")
	}
	if record.PublicationSeq == 0 && len(record.Parent) != 0 {
		return violation(ErrInvalidRecord, "parent", "genesis_nonempty")
	}
	if record.PublicationSeq != 0 && len(record.Parent) == 0 {
		return violation(ErrInvalidRecord, "parent", "missing")
	}
	if len(record.Parent) > MaxCIDBytes {
		return violation(ErrInvalidRecord, "parent", "length")
	}
	if len(record.Parent) != 0 {
		if _, err := castCID(record.Parent, cid.DagCBOR, "parent"); err != nil {
			return err
		}
	}
	if record.Blob.Size == 0 || record.Blob.Size > MaxBlobBytes {
		return violation(ErrInvalidRecord, "blob.size", "range")
	}
	if _, err := castCID(record.Blob.CID, cid.Raw, "blob.ref"); err != nil {
		return err
	}
	return nil
}

func validateHead(record HeadRecord) error {
	if record.SchemaVersion != SchemaVersion {
		return violation(ErrInvalidRecord, "schemaVersion", "unsupported")
	}
	if allZero(record.Vault[:]) {
		return violation(ErrInvalidRecord, "vault", "zero")
	}
	if record.PublicationSeq > MaxSequence {
		return violation(ErrInvalidRecord, "publicationSeq", "range")
	}
	if _, err := castCID(record.SnapshotCID, cid.DagCBOR, "snapshotCid"); err != nil {
		return err
	}
	if _, err := castCID(record.BlobCID, cid.Raw, "blobCid"); err != nil {
		return err
	}
	return nil
}

func castCID(encoded []byte, codec uint64, field string) (cid.Cid, error) {
	if len(encoded) == 0 || len(encoded) > MaxCIDBytes {
		return cid.Undef, violation(ErrCID, field, "length")
	}
	return validateCID(encoded, codec, field)
}

func validateCID(encoded []byte, codec uint64, field string) (cid.Cid, error) {
	if len(encoded) == 0 || len(encoded) > MaxCIDBytes {
		return cid.Undef, violation(ErrCID, field, "length")
	}
	identifier, err := cid.Cast(encoded)
	if err != nil || !bytes.Equal(identifier.Bytes(), encoded) {
		return cid.Undef, violation(ErrCID, field, "encoding")
	}
	prefix := identifier.Prefix()
	if prefix.Version != 1 || prefix.Codec != codec || prefix.MhType != multihash.SHA2_256 || prefix.MhLength != 32 {
		return cid.Undef, violation(ErrCID, field, "role")
	}
	return identifier, nil
}

func integer(value any) (int64, bool) {
	switch item := value.(type) {
	case int64:
		return item, true
	case int:
		return int64(item), true
	default:
		return 0, false
	}
}

func unsignedInteger(value any) (uint64, bool) {
	item, ok := integer(value)
	if !ok || item < 0 || uint64(item) > MaxSequence {
		return 0, false
	}
	return uint64(item), true
}

func byteString(value any) ([]byte, bool) {
	switch item := value.(type) {
	case []byte:
		return item, true
	case atdata.Bytes:
		return []byte(item), true
	default:
		return nil, false
	}
}

func allZero(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}

func violation(cause error, field, reason string) error {
	return &Violation{cause: cause, field: field, reason: reason}
}
