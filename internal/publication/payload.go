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
	PayloadFormPacked  PayloadForm = "packed"
	PayloadFormFileSet PayloadForm = "file_set"

	FileSetReasonPackedRequired = "packed_payload_required"
	FileSetReasonEntryCount     = "entry_count"
	FileSetReasonEntryBytes     = "entry_bytes"
	FileSetReasonTotalBytes     = "total_bytes"
	FileSetReasonUnavailable    = "entry_unavailable"
	FileSetReasonMismatch       = "entry_mismatch"
)

var ErrFileSetPayload = errors.New("publication file-set payload")

type FileSetPayloadError struct {
	Entry  string
	Reason string
	cause  error
}

func (e *FileSetPayloadError) Error() string {
	if e.Entry == "" {
		return "publication file-set payload: " + e.Reason
	}
	return "publication file-set payload: " + strconv.Quote(e.Entry) + ": " + e.Reason
}

func (e *FileSetPayloadError) Is(target error) bool { return target == ErrFileSetPayload }

func (e *FileSetPayloadError) Unwrap() error { return e.cause }

func (e *FileSetPayloadError) EntryPath() string { return e.Entry }

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
		return model.Snapshot{}, &FileSetPayloadError{Reason: FileSetReasonPackedRequired}
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
		return PayloadFormFileSet
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
	return resolveFileSetPayload(record.Entries, limits, fetch)
}

func resolveFileSetPayload(entries []SnapshotEntry, limits PayloadLimits, fetch PayloadFetch) (Payload, error) {
	if len(entries) == 0 {
		return Payload{}, &FileSetPayloadError{Reason: FileSetReasonEntryCount}
	}
	if limits.MaxEntries > 0 && len(entries) > limits.MaxEntries {
		return Payload{}, &FileSetPayloadError{Reason: FileSetReasonEntryCount}
	}
	resolved := make([]PayloadEntry, 0, len(entries))
	var total uint64
	for _, entry := range entries {
		if limits.MaxEntryBytes != 0 && entry.Size > limits.MaxEntryBytes {
			return Payload{}, &FileSetPayloadError{Entry: entry.Path, Reason: FileSetReasonEntryBytes}
		}
		total += entry.Size
		if limits.MaxTotalBytes != 0 && total > limits.MaxTotalBytes {
			return Payload{}, &FileSetPayloadError{Entry: entry.Path, Reason: FileSetReasonTotalBytes}
		}
		content, err := fetch(entry.Blob)
		if err != nil {
			return Payload{}, &FileSetPayloadError{
				Entry: entry.Path, Reason: FileSetReasonUnavailable, cause: err,
			}
		}
		if err := VerifyPayload(content, entry.Blob); err != nil {
			return Payload{}, &FileSetPayloadError{
				Entry: entry.Path, Reason: FileSetReasonMismatch, cause: err,
			}
		}
		resolved = append(resolved, PayloadEntry{
			Path: entry.Path, Mode: entry.Mode, Size: entry.Size, Content: content,
		})
	}
	return Payload{Form: PayloadFormFileSet, Entries: resolved}, nil
}
