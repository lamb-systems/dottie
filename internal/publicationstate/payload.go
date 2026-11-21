package publicationstate

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/lamb-systems/dottie/internal/publication"
)

type PayloadForm string

const (
	PayloadFormPacked   PayloadForm = PayloadForm(publication.PayloadFormPacked)
	PayloadFormManifest PayloadForm = PayloadForm(publication.PayloadFormManifest)
)

type PayloadEntryReference struct {
	Path string
	CID  []byte
	Size uint64
}

type ManifestPayload struct {
	Entries []PayloadEntryReference
}

type MaterialInput struct {
	Payload []byte
	Entries []publication.PayloadEntry
}

func (p ManifestPayload) EntryCount() uint32 { return uint32(len(p.Entries)) }

func (p ManifestPayload) TotalBytes() uint64 {
	var total uint64
	for _, entry := range p.Entries {
		total += entry.Size
	}
	return total
}

func cloneManifestPayload(payload *ManifestPayload) *ManifestPayload {
	if payload == nil {
		return nil
	}
	entries := make([]PayloadEntryReference, 0, len(payload.Entries))
	for _, entry := range payload.Entries {
		entries = append(entries, PayloadEntryReference{
			Path: entry.Path,
			CID:  bytes.Clone(entry.CID),
			Size: entry.Size,
		})
	}
	return &ManifestPayload{Entries: entries}
}

func payloadFormOf(record publication.SnapshotRecord) PayloadForm {
	return PayloadForm(record.PayloadForm())
}

func manifestPayloadOf(record publication.SnapshotRecord) *ManifestPayload {
	if len(record.Entries) == 0 {
		return nil
	}
	entries := make([]PayloadEntryReference, 0, len(record.Entries))
	for _, entry := range record.Entries {
		entries = append(entries, PayloadEntryReference{
			Path: entry.Path,
			CID:  bytes.Clone(entry.Blob.CID),
			Size: entry.Size,
		})
	}
	return &ManifestPayload{Entries: entries}
}

func validateManifestPayload(payload *ManifestPayload) error {
	if payload == nil || len(payload.Entries) == 0 {
		return errors.New("manifest payload")
	}
	if len(payload.Entries) > publication.MaxSnapshotEntries {
		return &manifestCapacityError{
			element: manifestCapacityEntryCount,
			have:    uint64(len(payload.Entries)),
			limit:   publication.MaxSnapshotEntries,
		}
	}
	for _, entry := range payload.Entries {
		if entry.Path == "" || len(entry.Path) > publication.MaxEntryPathBytes || entry.Size == 0 ||
			entry.Size > publication.MaxBlobBytes || len(entry.CID) == 0 || len(entry.CID) > publication.MaxCIDBytes {
			return errors.New("manifest payload")
		}
	}
	return nil
}

func validateManifestPayloadCustody(payload *ManifestPayload, limits AttemptLimits) error {
	if err := validateManifestPayload(payload); err != nil {
		return err
	}
	if uint64(len(payload.Entries)) > uint64(limits.ManagedObjects) {
		return &manifestCapacityError{
			element: manifestCapacityManagedObjects,
			have:    uint64(len(payload.Entries)),
			limit:   uint64(limits.ManagedObjects),
		}
	}
	if payload.TotalBytes() > limits.CustodyBytes {
		return &manifestCapacityError{
			element: manifestCapacityCustodyBytes,
			have:    payload.TotalBytes(),
			limit:   limits.CustodyBytes,
		}
	}
	return nil
}

func validateManifestMaterialLimits(payload *ManifestPayload, limits AttemptLimits) error {
	if err := validateManifestPayload(payload); err != nil {
		return err
	}
	distinct := make(map[string]bool, len(payload.Entries))
	for _, entry := range payload.Entries {
		distinct[string(entry.CID)] = true
	}
	if uint64(len(distinct)) > uint64(limits.ManagedObjects) {
		return &manifestCapacityError{
			element: manifestCapacityManagedObjects,
			have:    uint64(len(distinct)),
			limit:   uint64(limits.ManagedObjects),
		}
	}
	if payload.TotalBytes() > limits.CustodyBytes {
		return &manifestCapacityError{
			element: manifestCapacityCustodyBytes,
			have:    payload.TotalBytes(),
			limit:   limits.CustodyBytes,
		}
	}
	return nil
}

func manifestPayloadToWire(payload *ManifestPayload) []payloadEntryWire {
	if payload == nil {
		return nil
	}
	entries := make([]payloadEntryWire, 0, len(payload.Entries))
	for _, entry := range payload.Entries {
		entries = append(entries, payloadEntryWire{
			Path: entry.Path,
			CID:  bytes.Clone(entry.CID),
			Size: entry.Size,
		})
	}
	return entries
}

func manifestPayloadFromWire(entries []payloadEntryWire) (*ManifestPayload, error) {
	if len(entries) == 0 {
		return nil, errors.New("manifest payload")
	}
	payload := &ManifestPayload{Entries: make([]PayloadEntryReference, 0, len(entries))}
	for _, entry := range entries {
		if entry.Path == "" || len(entry.Path) > publication.MaxEntryPathBytes || entry.Size == 0 ||
			entry.Size > publication.MaxBlobBytes || len(entry.CID) == 0 || len(entry.CID) > publication.MaxCIDBytes {
			return nil, errors.New("manifest payload")
		}
		payload.Entries = append(payload.Entries, PayloadEntryReference{
			Path: entry.Path,
			CID:  bytes.Clone(entry.CID),
			Size: entry.Size,
		})
	}
	return payload, nil
}

func sameManifestPayload(left, right *ManifestPayload) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	if len(left.Entries) != len(right.Entries) {
		return false
	}
	for index, entry := range left.Entries {
		other := right.Entries[index]
		if entry.Path != other.Path || entry.Size != other.Size || !bytes.Equal(entry.CID, other.CID) {
			return false
		}
	}
	return true
}

func manifestPayloadMatchesRecord(snapshot *ManifestPayload, record publication.SnapshotRecord) bool {
	return sameManifestPayload(snapshot, manifestPayloadOf(record))
}

func floorPayloadMatchesRecord(floor Floor, record publication.SnapshotRecord) bool {
	if payloadFormOf(record) == PayloadFormManifest {
		return floor.Manifest != nil && len(floor.BlobCID) == 0 && floor.BlobSize == 0 &&
			manifestPayloadMatchesRecord(floor.Manifest, record)
	}
	return floor.Manifest == nil && bytes.Equal(record.Blob.CID, floor.BlobCID) && record.Blob.Size == floor.BlobSize
}

func validateFloorPayload(floor Floor) error {
	if floor.Manifest == nil {
		if len(floor.BlobCID) == 0 || len(floor.BlobCID) > publication.MaxCIDBytes {
			return errors.New("floor payload")
		}
		return nil
	}
	if len(floor.BlobCID) != 0 || floor.BlobSize != 0 {
		return errors.New("floor payload")
	}
	return validateManifestPayload(floor.Manifest)
}

func manifestPayloadUnsupported(stage Stage) error {
	return classified(ErrUnsupported, stage, ReasonPayloadForm)
}

func attemptCoreForm(core attemptCoreWire) PayloadForm {
	if core.Version == 2 {
		return PayloadFormManifest
	}
	return PayloadFormPacked
}

func requirePackedAttemptCore(core attemptCoreWire, stage Stage) error {
	if attemptCoreForm(core) != PayloadFormPacked {
		return manifestPayloadUnsupported(stage)
	}
	return nil
}

const (
	manifestCapacityEntryCount     = "manifest entry count"
	manifestCapacityManagedObjects = "manifest managed objects"
	manifestCapacityCustodyBytes   = "manifest custody bytes"
)

type manifestCapacityError struct {
	element string
	have    uint64
	limit   uint64
}

func (e *manifestCapacityError) Error() string {
	return fmt.Sprintf(
		"publication state: %s/%s/%s: %s: %d exceeds %d",
		className(ErrLimit),
		StageInput,
		ReasonCapacity,
		e.element,
		e.have,
		e.limit,
	)
}

func (e *manifestCapacityError) Unwrap() error {
	return classified(ErrLimit, StageInput, ReasonCapacity)
}

func encodeRetainedManifest(payload *ManifestPayload) ([]byte, error) {
	if err := validateManifestPayload(payload); err != nil {
		return nil, err
	}
	encoded, err := canonicalJSON(manifestPayloadToWire(payload))
	if err != nil || len(encoded) == 0 || len(encoded) > publication.MaxManifestRecordBytes {
		return nil, errors.New("retained manifest")
	}
	return encoded, nil
}

func decodeRetainedManifest(encoded []byte) (*ManifestPayload, error) {
	if len(encoded) == 0 || len(encoded) > publication.MaxManifestRecordBytes {
		return nil, errors.New("retained manifest")
	}
	var entries []payloadEntryWire
	if err := strictJSON(encoded, &entries); err != nil {
		return nil, errors.New("retained manifest")
	}
	payload, err := manifestPayloadFromWire(entries)
	if err != nil {
		return nil, errors.New("retained manifest")
	}
	if err := validateManifestPayload(payload); err != nil {
		return nil, errors.New("retained manifest")
	}
	return payload, nil
}
