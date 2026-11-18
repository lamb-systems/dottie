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
	PayloadFormManifest PayloadForm = "manifest"

	ManifestReasonPackedRequired = "packed_payload_required"
	ManifestReasonEntryCount     = "entry_count"
	ManifestReasonEntryBytes     = "entry_bytes"
	ManifestReasonTotalBytes     = "total_bytes"
	ManifestReasonUnavailable    = "entry_unavailable"
	ManifestReasonMismatch       = "entry_mismatch"
)

var ErrManifestPayload = errors.New("publication manifest payload")

type ManifestPayloadError struct {
	Entry  string
	Reason string
	cause  error
}

func (e *ManifestPayloadError) Error() string {
	if e.Entry == "" {
		return "publication manifest payload: " + e.Reason
	}
	return "publication manifest payload: " + strconv.Quote(e.Entry) + ": " + e.Reason
}

func (e *ManifestPayloadError) Is(target error) bool { return target == ErrManifestPayload }

func (e *ManifestPayloadError) Unwrap() error { return e.cause }

func (e *ManifestPayloadError) EntryPath() string { return e.Entry }

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
		return model.Snapshot{}, &ManifestPayloadError{Reason: ManifestReasonPackedRequired}
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
		return PayloadFormManifest
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
	return resolveManifestPayload(record.Entries, limits, fetch)
}

func resolveManifestPayload(entries []SnapshotEntry, limits PayloadLimits, fetch PayloadFetch) (Payload, error) {
	if len(entries) == 0 {
		return Payload{}, &ManifestPayloadError{Reason: ManifestReasonEntryCount}
	}
	if limits.MaxEntries > 0 && len(entries) > limits.MaxEntries {
		return Payload{}, &ManifestPayloadError{Reason: ManifestReasonEntryCount}
	}
	resolved := make([]PayloadEntry, 0, len(entries))
	var total uint64
	for _, entry := range entries {
		if limits.MaxEntryBytes != 0 && entry.Size > limits.MaxEntryBytes {
			return Payload{}, &ManifestPayloadError{Entry: entry.Path, Reason: ManifestReasonEntryBytes}
		}
		total += entry.Size
		if limits.MaxTotalBytes != 0 && total > limits.MaxTotalBytes {
			return Payload{}, &ManifestPayloadError{Entry: entry.Path, Reason: ManifestReasonTotalBytes}
		}
		content, err := fetch(entry.Blob)
		if err != nil {
			return Payload{}, &ManifestPayloadError{
				Entry: entry.Path, Reason: ManifestReasonUnavailable, cause: err,
			}
		}
		if err := VerifyPayload(content, entry.Blob); err != nil {
			return Payload{}, &ManifestPayloadError{
				Entry: entry.Path, Reason: ManifestReasonMismatch, cause: err,
			}
		}
		resolved = append(resolved, PayloadEntry{
			Path: entry.Path, Mode: entry.Mode, Size: entry.Size, Content: content,
		})
	}
	return Payload{Form: PayloadFormManifest, Entries: resolved}, nil
}
