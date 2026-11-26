package publication

import (
	"errors"
	"reflect"
	"sort"
	"strconv"
	"strings"

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

const payloadDirectoryMode uint32 = 0o755

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

// DecodeSegmentPayload decodes a packed segment payload and requires the archived
// snapshot to name exactly the segment target.
func DecodeSegmentPayload(payload []byte, segment SnapshotSegment) (model.Snapshot, error) {
	snapshot, err := DecodePayload(payload, segment.Blob)
	if err != nil {
		return model.Snapshot{}, err
	}
	if len(snapshot.Targets) != 1 || !reflect.DeepEqual(snapshot.Targets[0], segment.Target) {
		return model.Snapshot{}, &FileSetPayloadError{Reason: FileSetReasonMismatch}
	}
	return snapshot, nil
}

func ResolvePayload(record SnapshotRecord, limits PayloadLimits, fetch PayloadFetch) (Payload, error) {
	if err := checkResolvedPayloadLimits(record, limits); err != nil {
		return Payload{}, err
	}
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
			snapshot, err := DecodeSegmentPayload(raw, segment)
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
			projected, err := payloadSegmentEntries(segment.Target, entries)
			if err != nil {
				return Payload{}, err
			}
			payload.Snapshot.Entries = append(payload.Snapshot.Entries, projected...)
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
	if err := payload.Snapshot.Validate(); err != nil {
		return Payload{}, &FileSetPayloadError{Reason: FileSetReasonMismatch}
	}
	return payload, nil
}

func checkResolvedPayloadLimits(record SnapshotRecord, limits PayloadLimits) error {
	var total uint64
	for _, segment := range record.Segments {
		switch segment.Form {
		case SegmentFormPacked:
			if ^uint64(0)-total < segment.Blob.Size {
				return &FileSetPayloadError{Reason: FileSetReasonTotalBytes}
			}
			total += segment.Blob.Size
			if limits.MaxTotalBytes != 0 && total > limits.MaxTotalBytes {
				return &FileSetPayloadError{Reason: FileSetReasonTotalBytes}
			}
		case SegmentFormEntries:
			if limits.MaxEntries > 0 && len(segment.Entries) > limits.MaxEntries {
				return &FileSetPayloadError{Reason: FileSetReasonEntryCount}
			}
			for _, entry := range segment.Entries {
				if limits.MaxEntryBytes != 0 && entry.Size > limits.MaxEntryBytes {
					return &FileSetPayloadError{Entry: entry.Path, Reason: FileSetReasonEntryBytes}
				}
				if ^uint64(0)-total < entry.Size {
					return &FileSetPayloadError{Entry: entry.Path, Reason: FileSetReasonTotalBytes}
				}
				total += entry.Size
				if limits.MaxTotalBytes != 0 && total > limits.MaxTotalBytes {
					return &FileSetPayloadError{Entry: entry.Path, Reason: FileSetReasonTotalBytes}
				}
			}
		}
	}
	if limits.MaxTotalBytes != 0 && total > limits.MaxTotalBytes {
		return &FileSetPayloadError{Reason: FileSetReasonTotalBytes}
	}
	return nil
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

func payloadSegmentEntries(target model.Target, entries []PayloadEntry) ([]model.Entry, error) {
	singleFile := target.Root != nil && target.Root.Kind == model.SelectionFile
	projected := make([]model.Entry, 0, len(entries))
	directories := make(map[string]struct{})
	files := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if entry.Path == "" || entry.Path == "." {
			return nil, &FileSetPayloadError{Entry: entry.Path, Reason: FileSetReasonMismatch}
		}
		if _, duplicate := files[entry.Path]; duplicate {
			return nil, &FileSetPayloadError{Entry: entry.Path, Reason: FileSetReasonMismatch}
		}
		files[entry.Path] = struct{}{}
		entryPath := entry.Path
		if singleFile {
			entryPath = "."
		}
		projected = append(projected, model.Entry{
			TargetID: target.ID,
			File: &model.FileEntry{
				Path: entryPath, State: model.FilePresent, Kind: model.FileRegular,
				Content: entry.Content, Mode: entry.Mode,
			},
		})
		if singleFile {
			continue
		}
		for parent := payloadEntryParent(entry.Path); parent != "."; parent = payloadEntryParent(parent) {
			if _, conflict := files[parent]; conflict {
				return nil, &FileSetPayloadError{Entry: parent, Reason: FileSetReasonMismatch}
			}
			directories[parent] = struct{}{}
		}
	}
	for path := range directories {
		projected = append(projected, model.Entry{
			TargetID: target.ID,
			File: &model.FileEntry{
				Path: path, State: model.FilePresent, Kind: model.FileDirectory,
				Mode: payloadDirectoryMode,
			},
		})
	}
	sort.Slice(projected, func(left, right int) bool {
		return payloadEntryPathLess(projected[left].File.Path, projected[right].File.Path)
	})
	return projected, nil
}

func payloadEntryParent(path string) string {
	index := strings.LastIndexByte(path, '/')
	if index < 0 {
		return "."
	}
	return path[:index]
}

func payloadEntryPathLess(left, right string) bool {
	leftDepth := strings.Count(left, "/")
	rightDepth := strings.Count(right, "/")
	if leftDepth != rightDepth {
		return leftDepth < rightDepth
	}
	return left < right
}
