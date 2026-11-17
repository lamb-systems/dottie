package publication

import (
	"errors"
	"strconv"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/vault"
)

func DecodePayload(payload []byte, reference BlobReference) (model.Snapshot, error) {
	if err := VerifyPayload(payload, reference); err != nil {
		return model.Snapshot{}, err
	}
	snapshot, err := vault.UnpackPayload(payload)
	if err != nil {
		return model.Snapshot{}, err
	}
	return snapshot, nil
}

type PayloadForm string

const (
	PayloadFormPacked   PayloadForm = "packed"
	PayloadFormShowcase PayloadForm = "showcase"

	ShowcaseReasonPackedRequired = "packed_payload_required"
	ShowcaseReasonEntryCount     = "entry_count"
	ShowcaseReasonEntryBytes     = "entry_bytes"
	ShowcaseReasonTotalBytes     = "total_bytes"
	ShowcaseReasonUnavailable    = "entry_unavailable"
	ShowcaseReasonMismatch       = "entry_mismatch"
)

var ErrShowcasePayload = errors.New("publication showcase payload")

type ShowcasePayloadError struct {
	Entry  string
	Reason string
	cause  error
}

func (e *ShowcasePayloadError) Error() string {
	if e.Entry == "" {
		return "publication showcase payload: " + e.Reason
	}
	return "publication showcase payload: " + strconv.Quote(e.Entry) + ": " + e.Reason
}

func (e *ShowcasePayloadError) Is(target error) bool { return target == ErrShowcasePayload }

func (e *ShowcasePayloadError) Unwrap() error { return e.cause }

func (e *ShowcasePayloadError) EntryPath() string { return e.Entry }

type PayloadEntry struct {
	Path    string
	Mode    uint32
	Size    uint64
	Content []byte
}

type Payload struct {
	Form     PayloadForm
	Snapshot model.Snapshot
	Entries  []PayloadEntry
}

func (payload Payload) PackedSnapshot() (model.Snapshot, error) {
	if payload.Form != PayloadFormPacked {
		return model.Snapshot{}, &ShowcasePayloadError{Reason: ShowcaseReasonPackedRequired}
	}
	return payload.Snapshot, nil
}

type PayloadLimits struct {
	MaxEntries    int
	MaxEntryBytes uint64
	MaxTotalBytes uint64
}

type PayloadFetch func(reference BlobReference) ([]byte, error)

func (record SnapshotRecord) PayloadForm() PayloadForm {
	if len(record.Entries) != 0 {
		return PayloadFormShowcase
	}
	return PayloadFormPacked
}

func ResolvePayload(record SnapshotRecord, limits PayloadLimits, fetch PayloadFetch) (Payload, error) {
	if record.PayloadForm() == PayloadFormPacked {
		payload, err := fetch(record.Blob)
		if err != nil {
			return Payload{}, err
		}
		snapshot, err := DecodePayload(payload, record.Blob)
		if err != nil {
			return Payload{}, err
		}
		return Payload{Form: PayloadFormPacked, Snapshot: snapshot}, nil
	}
	return resolveShowcasePayload(record.Entries, limits, fetch)
}

func resolveShowcasePayload(entries []SnapshotEntry, limits PayloadLimits, fetch PayloadFetch) (Payload, error) {
	if len(entries) == 0 {
		return Payload{}, &ShowcasePayloadError{Reason: ShowcaseReasonEntryCount}
	}
	if limits.MaxEntries > 0 && len(entries) > limits.MaxEntries {
		return Payload{}, &ShowcasePayloadError{Reason: ShowcaseReasonEntryCount}
	}
	resolved := make([]PayloadEntry, 0, len(entries))
	var total uint64
	for _, entry := range entries {
		if limits.MaxEntryBytes != 0 && entry.Size > limits.MaxEntryBytes {
			return Payload{}, &ShowcasePayloadError{Entry: entry.Path, Reason: ShowcaseReasonEntryBytes}
		}
		total += entry.Size
		if limits.MaxTotalBytes != 0 && total > limits.MaxTotalBytes {
			return Payload{}, &ShowcasePayloadError{Entry: entry.Path, Reason: ShowcaseReasonTotalBytes}
		}
		content, err := fetch(entry.Blob)
		if err != nil {
			return Payload{}, &ShowcasePayloadError{
				Entry: entry.Path, Reason: ShowcaseReasonUnavailable, cause: err,
			}
		}
		if err := VerifyPayload(content, entry.Blob); err != nil {
			return Payload{}, &ShowcasePayloadError{
				Entry: entry.Path, Reason: ShowcaseReasonMismatch, cause: err,
			}
		}
		resolved = append(resolved, PayloadEntry{
			Path: entry.Path, Mode: entry.Mode, Size: entry.Size, Content: content,
		})
	}
	return Payload{Form: PayloadFormShowcase, Entries: resolved}, nil
}
