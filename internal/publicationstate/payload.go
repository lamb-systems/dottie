package publicationstate

import (
	"bytes"
	"errors"

	"github.com/lamb-systems/dottie/internal/publication"
)

type PayloadForm string

const (
	PayloadFormPacked   PayloadForm = PayloadForm(publication.PayloadFormPacked)
	PayloadFormShowcase PayloadForm = PayloadForm(publication.PayloadFormShowcase)
)

type PayloadEntryReference struct {
	Path string
	CID  []byte
	Size uint64
}

type ShowcasePayload struct {
	Entries []PayloadEntryReference
}

func (p ShowcasePayload) EntryCount() uint32 { return uint32(len(p.Entries)) }

func (p ShowcasePayload) TotalBytes() uint64 {
	var total uint64
	for _, entry := range p.Entries {
		total += entry.Size
	}
	return total
}

func cloneShowcasePayload(payload *ShowcasePayload) *ShowcasePayload {
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
	return &ShowcasePayload{Entries: entries}
}

func payloadFormOf(record publication.SnapshotRecord) PayloadForm {
	return PayloadForm(record.PayloadForm())
}

func showcasePayloadOf(record publication.SnapshotRecord) *ShowcasePayload {
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
	return &ShowcasePayload{Entries: entries}
}

func validateShowcasePayload(payload *ShowcasePayload) error {
	if payload == nil || len(payload.Entries) == 0 || len(payload.Entries) > publication.MaxSnapshotEntries {
		return errors.New("showcase payload")
	}
	for _, entry := range payload.Entries {
		if entry.Path == "" || len(entry.Path) > publication.MaxEntryPathBytes || entry.Size == 0 ||
			entry.Size > publication.MaxBlobBytes || len(entry.CID) == 0 || len(entry.CID) > publication.MaxCIDBytes {
			return errors.New("showcase payload")
		}
	}
	return nil
}

func validateShowcasePayloadCustody(payload *ShowcasePayload, limits AttemptLimits) error {
	if err := validateShowcasePayload(payload); err != nil {
		return err
	}
	if uint64(len(payload.Entries)) > uint64(limits.ManagedObjects) {
		return errShowcaseManagedObjects
	}
	if payload.TotalBytes() > limits.CustodyBytes {
		return errShowcaseCustodyBytes
	}
	return nil
}

func showcasePayloadToWire(payload *ShowcasePayload) []payloadEntryWire {
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

func showcasePayloadFromWire(entries []payloadEntryWire) (*ShowcasePayload, error) {
	if len(entries) == 0 {
		return nil, errors.New("showcase payload")
	}
	payload := &ShowcasePayload{Entries: make([]PayloadEntryReference, 0, len(entries))}
	for _, entry := range entries {
		if entry.Path == "" || len(entry.Path) > publication.MaxEntryPathBytes || entry.Size == 0 ||
			entry.Size > publication.MaxBlobBytes || len(entry.CID) == 0 || len(entry.CID) > publication.MaxCIDBytes {
			return nil, errors.New("showcase payload")
		}
		payload.Entries = append(payload.Entries, PayloadEntryReference{
			Path: entry.Path,
			CID:  bytes.Clone(entry.CID),
			Size: entry.Size,
		})
	}
	return payload, nil
}

func sameShowcasePayload(left, right *ShowcasePayload) bool {
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

func showcasePayloadMatchesRecord(snapshot *ShowcasePayload, record publication.SnapshotRecord) bool {
	return sameShowcasePayload(snapshot, showcasePayloadOf(record))
}

func floorPayloadMatchesRecord(floor Floor, record publication.SnapshotRecord) bool {
	if payloadFormOf(record) == PayloadFormShowcase {
		return floor.Showcase != nil && len(floor.BlobCID) == 0 && floor.BlobSize == 0 &&
			showcasePayloadMatchesRecord(floor.Showcase, record)
	}
	return floor.Showcase == nil && bytes.Equal(record.Blob.CID, floor.BlobCID) && record.Blob.Size == floor.BlobSize
}

func validateFloorPayload(floor Floor) error {
	if floor.Showcase == nil {
		if len(floor.BlobCID) == 0 || len(floor.BlobCID) > publication.MaxCIDBytes {
			return errors.New("floor payload")
		}
		return nil
	}
	if len(floor.BlobCID) != 0 || floor.BlobSize != 0 {
		return errors.New("floor payload")
	}
	return validateShowcasePayload(floor.Showcase)
}

func showcasePayloadUnsupported(stage Stage) error {
	return classified(ErrUnsupported, stage, ReasonPayloadForm)
}

func requirePackedAttemptCore(core attemptCoreWire, stage Stage) error {
	if core.Version != 1 || len(core.Entries) != 0 {
		return showcasePayloadUnsupported(stage)
	}
	return nil
}

var (
	errShowcaseManagedObjects = errors.New("showcase payload managed objects")
	errShowcaseCustodyBytes   = errors.New("showcase payload custody bytes")
)
