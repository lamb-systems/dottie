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
	PayloadFormFileSet  PayloadForm = "file_set"
	PayloadFormSettings PayloadForm = "settings"
	PayloadFormMixed    PayloadForm = "mixed"

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
	if len(record.Segments) != 1 {
		return PayloadFormMixed
	}
	switch record.Segments[0].Form {
	case SegmentFormEntries:
		return PayloadFormFileSet
	case SegmentFormSettings:
		return PayloadFormSettings
	case SegmentFormPacked:
		return PayloadFormPacked
	default:
		return PayloadFormMixed
	}
}

func ResolvePayload(record SnapshotRecord, limits PayloadLimits, fetch PayloadFetch) (Payload, error) {
	payload := Payload{Form: record.PayloadForm()}
	payload.Snapshot = model.Snapshot{Version: model.SnapshotVersion}
	for _, segment := range record.Segments {
		payload.Snapshot.Targets = append(payload.Snapshot.Targets, cloneTarget(segment.Target))
		switch segment.Form {
		case SegmentFormPacked:
			raw, err := fetch(segment.Blob)
			if err != nil {
				return Payload{}, err
			}
			snapshot, err := DecodePayload(raw, segment.Blob)
			if err != nil {
				return Payload{}, err
			}
			payload.Snapshot.Entries = append(payload.Snapshot.Entries, snapshot.Entries...)
		case SegmentFormEntries:
			entries, err := resolvePayloadEntries(segment.Entries, limits, fetch)
			if err != nil {
				return Payload{}, err
			}
			payload.Entries = append(payload.Entries, entries...)
			for _, entry := range entries {
				payload.Snapshot.Entries = append(payload.Snapshot.Entries, model.Entry{
					TargetID: segment.Target.ID,
					File: &model.FileEntry{
						Path: entry.Path, State: model.FilePresent, Kind: model.FileRegular,
						Content: entry.Content, Mode: entry.Mode,
					},
				})
			}
		case SegmentFormSettings:
			for _, setting := range segment.Settings {
				payload.Snapshot.Entries = append(payload.Snapshot.Entries, model.Entry{
					TargetID: segment.Target.ID,
					Setting: &model.SettingEntry{
						SchemaID: setting.SchemaID, Path: setting.Path, Key: setting.Key,
						State: setting.State, Value: cloneVariantValue(setting.Value),
					},
				})
			}
		default:
			return Payload{}, &FileSetPayloadError{Reason: FileSetReasonPackedRequired}
		}
	}
	return payload, nil
}

func resolvePayloadEntries(entries []SnapshotEntry, limits PayloadLimits, fetch PayloadFetch) ([]PayloadEntry, error) {
	if len(entries) == 0 {
		return nil, &FileSetPayloadError{Reason: FileSetReasonEntryCount}
	}
	if limits.MaxEntries > 0 && len(entries) > limits.MaxEntries {
		return nil, &FileSetPayloadError{Reason: FileSetReasonEntryCount}
	}
	resolved := make([]PayloadEntry, 0, len(entries))
	var total uint64
	for _, entry := range entries {
		if limits.MaxEntryBytes != 0 && entry.Size > limits.MaxEntryBytes {
			return nil, &FileSetPayloadError{Entry: entry.Path, Reason: FileSetReasonEntryBytes}
		}
		total += entry.Size
		if limits.MaxTotalBytes != 0 && total > limits.MaxTotalBytes {
			return nil, &FileSetPayloadError{Entry: entry.Path, Reason: FileSetReasonTotalBytes}
		}
		content, err := fetch(entry.Blob)
		if err != nil {
			return nil, &FileSetPayloadError{Entry: entry.Path, Reason: FileSetReasonUnavailable, cause: err}
		}
		if err := VerifyPayload(content, entry.Blob); err != nil {
			return nil, &FileSetPayloadError{Entry: entry.Path, Reason: FileSetReasonMismatch, cause: err}
		}
		resolved = append(resolved, PayloadEntry{Path: entry.Path, Mode: entry.Mode, Size: entry.Size, Content: content})
	}
	return resolved, nil
}

func cloneTarget(target model.Target) model.Target {
	cloned := model.Target{ID: target.ID, Source: target.Source, SourceVersion: target.SourceVersion}
	if target.Root != nil {
		root := *target.Root
		cloned.Root = &root
	}
	return cloned
}

func cloneVariantValue(value *model.VariantValue) *model.VariantValue {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
