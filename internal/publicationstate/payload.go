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
	PayloadFormFileSet  PayloadForm = PayloadForm(publication.PayloadFormFileSet)
	PayloadFormSettings PayloadForm = PayloadForm(publication.PayloadFormSettings)
)

type PayloadEntryReference struct {
	Path string
	CID  []byte
	Size uint64
}

type FileSetPayload struct {
	Entries []PayloadEntryReference
}

type MaterialInput struct {
	Payload  []byte
	Payloads [][]byte
	Entries  []publication.PayloadEntry
}

type CandidateSegments struct {
	Segments []CandidateSegment
	Payloads [][]byte
}

func (p FileSetPayload) EntryCount() uint32 { return uint32(len(p.Entries)) }

func (p FileSetPayload) TotalBytes() uint64 {
	var total uint64
	for _, entry := range p.Entries {
		total += entry.Size
	}
	return total
}

func fileSetPayloadOf(record publication.SnapshotRecord) *FileSetPayload {
	recordEntries, _ := record.SegmentEntries()
	if len(recordEntries) == 0 {
		return nil
	}
	entries := make([]PayloadEntryReference, 0, len(recordEntries))
	for _, entry := range recordEntries {
		entries = append(entries, PayloadEntryReference{
			Path: entry.Path,
			CID:  bytes.Clone(entry.Blob.CID),
			Size: entry.Size,
		})
	}
	return &FileSetPayload{Entries: entries}
}

func validateFileSetPayload(payload *FileSetPayload) error {
	if payload == nil || len(payload.Entries) == 0 {
		return errors.New("file-set payload")
	}
	if len(payload.Entries) > publication.MaxSnapshotEntries {
		return &fileSetCapacityError{
			element: fileSetCapacityEntryCount,
			have:    uint64(len(payload.Entries)),
			limit:   publication.MaxSnapshotEntries,
		}
	}
	for _, entry := range payload.Entries {
		if entry.Path == "" || len(entry.Path) > publication.MaxEntryPathBytes || entry.Size == 0 ||
			entry.Size > publication.MaxBlobBytes || len(entry.CID) == 0 || len(entry.CID) > publication.MaxCIDBytes {
			return errors.New("file-set payload")
		}
	}
	return nil
}

func validateFileSetPayloadCustody(payload *FileSetPayload, limits AttemptLimits) error {
	if err := validateFileSetPayload(payload); err != nil {
		return err
	}
	if uint64(len(payload.Entries)) > uint64(limits.ManagedObjects) {
		return &fileSetCapacityError{
			element: fileSetCapacityManagedObjects,
			have:    uint64(len(payload.Entries)),
			limit:   uint64(limits.ManagedObjects),
		}
	}
	if payload.TotalBytes() > limits.CustodyBytes {
		return &fileSetCapacityError{
			element: fileSetCapacityCustodyBytes,
			have:    payload.TotalBytes(),
			limit:   limits.CustodyBytes,
		}
	}
	return nil
}

func validateFileSetMaterialLimits(payload *FileSetPayload, limits AttemptLimits) error {
	if err := validateFileSetPayload(payload); err != nil {
		return err
	}
	distinct := make(map[string]bool, len(payload.Entries))
	for _, entry := range payload.Entries {
		distinct[string(entry.CID)] = true
	}
	if uint64(len(distinct)) > uint64(limits.ManagedObjects) {
		return &fileSetCapacityError{
			element: fileSetCapacityManagedObjects,
			have:    uint64(len(distinct)),
			limit:   uint64(limits.ManagedObjects),
		}
	}
	if payload.TotalBytes() > limits.CustodyBytes {
		return &fileSetCapacityError{
			element: fileSetCapacityCustodyBytes,
			have:    payload.TotalBytes(),
			limit:   limits.CustodyBytes,
		}
	}
	return nil
}

func fileSetPayloadToWire(payload *FileSetPayload) []payloadEntryWire {
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

func fileSetPayloadFromWire(entries []payloadEntryWire) (*FileSetPayload, error) {
	if len(entries) == 0 {
		return nil, errors.New("file-set payload")
	}
	payload := &FileSetPayload{Entries: make([]PayloadEntryReference, 0, len(entries))}
	for _, entry := range entries {
		if entry.Path == "" || len(entry.Path) > publication.MaxEntryPathBytes || entry.Size == 0 ||
			entry.Size > publication.MaxBlobBytes || len(entry.CID) == 0 || len(entry.CID) > publication.MaxCIDBytes {
			return nil, errors.New("file-set payload")
		}
		payload.Entries = append(payload.Entries, PayloadEntryReference{
			Path: entry.Path,
			CID:  bytes.Clone(entry.CID),
			Size: entry.Size,
		})
	}
	return payload, nil
}

func sameFileSetPayload(left, right *FileSetPayload) bool {
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

func floorPayloadMatchesRecord(floor Floor, record publication.SnapshotRecord) bool {
	return sameSegmentSummaries(floor.Segments, summariesOfRecord(record.Segments))
}

func validateFloorPayload(floor Floor) error {
	return validateSegmentSummaries(floor.Segments)
}

func validateSegmentMaterialLimits(summary SegmentSummary, limits AttemptLimits) error {
	distinct := make(map[string]bool, len(summary.Entries))
	var total uint64
	for _, entry := range summary.Entries {
		distinct[string(entry.CID)] = true
		total += entry.Size
	}
	if uint64(len(distinct)) > uint64(limits.ManagedObjects) {
		return &fileSetCapacityError{
			element: fileSetCapacityManagedObjects,
			have:    uint64(len(distinct)),
			limit:   uint64(limits.ManagedObjects),
		}
	}
	if total > limits.CustodyBytes {
		return &fileSetCapacityError{
			element: fileSetCapacityCustodyBytes,
			have:    total,
			limit:   limits.CustodyBytes,
		}
	}
	return nil
}

func fileSetPayloadUnsupported(stage Stage) error {
	return classified(ErrUnsupported, stage, ReasonPayloadForm)
}

func attemptCoreForm(core attemptCoreWire) PayloadForm {
	segments, err := segmentSummariesFromWire(core.Segments)
	if err != nil || len(segments) == 0 {
		return ""
	}
	form := PayloadFormPacked
	for _, segment := range segments {
		switch segment.Form {
		case PayloadFormSettings:
			if len(segments) == 1 {
				return PayloadFormSettings
			}
		case PayloadFormFileSet:
			form = PayloadFormFileSet
		case PayloadFormPacked:
		}
	}
	return form
}

const (
	fileSetCapacityEntryCount     = "file-set entry count"
	fileSetCapacityManagedObjects = "file-set managed objects"
	fileSetCapacityCustodyBytes   = "file-set custody bytes"
)

type fileSetCapacityError struct {
	element string
	have    uint64
	limit   uint64
}

func (e *fileSetCapacityError) Error() string {
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

func (e *fileSetCapacityError) Unwrap() error {
	return classified(ErrLimit, StageInput, ReasonCapacity)
}

func encodeRetainedFileSet(payload *FileSetPayload) ([]byte, error) {
	if err := validateFileSetPayload(payload); err != nil {
		return nil, err
	}
	encoded, err := canonicalJSON(fileSetPayloadToWire(payload))
	if err != nil || len(encoded) == 0 || len(encoded) > publication.MaxFileSetRecordBytes {
		return nil, errors.New("retained file-set")
	}
	return encoded, nil
}

func decodeRetainedFileSet(encoded []byte) (*FileSetPayload, error) {
	if len(encoded) == 0 || len(encoded) > publication.MaxFileSetRecordBytes {
		return nil, errors.New("retained file-set")
	}
	var entries []payloadEntryWire
	if err := strictJSON(encoded, &entries); err != nil {
		return nil, errors.New("retained file-set")
	}
	payload, err := fileSetPayloadFromWire(entries)
	if err != nil {
		return nil, errors.New("retained file-set")
	}
	if err := validateFileSetPayload(payload); err != nil {
		return nil, errors.New("retained file-set")
	}
	return payload, nil
}
