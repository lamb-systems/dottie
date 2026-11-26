package publication

import (
	"crypto/sha256"
	"encoding/json"
	"path"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/ipfs/go-cid"

	"github.com/lamb-systems/dottie/internal/model"
)

const MaxSnapshotSettings = 256

type SegmentForm string

const (
	SegmentFormEntries  SegmentForm = "entries"
	SegmentFormSettings SegmentForm = "settings"
	SegmentFormPacked   SegmentForm = "packed"
)

type SnapshotSegment struct {
	Target   model.Target
	Form     SegmentForm
	Entries  []SnapshotEntry
	Settings []SnapshotSetting
	Blob     BlobReference
}

type SnapshotSetting struct {
	SchemaID string
	Path     string
	Key      string
	State    model.SettingState
	Value    *model.VariantValue
}

func validateSegment(segment SnapshotSegment) error {
	if err := segment.Target.Validate(); err != nil {
		return violation(ErrInvalidRecord, "segments.target", "unsupported")
	}
	root := segment.Target.Root
	switch segment.Form {
	case SegmentFormEntries:
		if segment.Target.Source != model.SourceFiles || root == nil ||
			len(segment.Settings) != 0 || !segmentBlobEmpty(segment.Blob) {
			return violation(ErrInvalidRecord, "segments.form", "entries")
		}
		if err := validateEntries(segment.Entries); err != nil {
			return err
		}
		if root.Kind == model.SelectionFile &&
			(len(segment.Entries) != 1 || segment.Entries[0].Path != path.Base(root.Path)) {
			return violation(ErrInvalidRecord, "segments.target", "mismatch")
		}
		return nil
	case SegmentFormSettings:
		if segment.Target.Source != model.SourceGNOME || root != nil ||
			len(segment.Entries) != 0 || !segmentBlobEmpty(segment.Blob) {
			return violation(ErrInvalidRecord, "segments.form", "settings")
		}
		return validateSettings(segment.Settings)
	case SegmentFormPacked:
		if segment.Target.Source != model.SourceFiles || root == nil ||
			len(segment.Entries) != 0 || len(segment.Settings) != 0 {
			return violation(ErrInvalidRecord, "segments.form", "packed")
		}
		if segment.Blob.Size == 0 || segment.Blob.Size > MaxBlobBytes ||
			segment.Blob.MIMEType != SnapshotBlobMIMEType {
			return violation(ErrInvalidRecord, "segments.blob", "unsupported")
		}
		_, err := castCID(segment.Blob.CID, cid.Raw, "segments.blob.ref")
		return err
	default:
		return violation(ErrInvalidRecord, "segments.form", "unsupported")
	}
}

func segmentBlobEmpty(blob BlobReference) bool {
	return len(blob.CID) == 0 && blob.Size == 0 && blob.MIMEType == ""
}

func validateSettings(settings []SnapshotSetting) error {
	if len(settings) == 0 || len(settings) > MaxSnapshotSettings {
		return violation(ErrInvalidRecord, "segments.settings", "count")
	}
	previous := ""
	for index, setting := range settings {
		entry := model.SettingEntry{
			SchemaID: setting.SchemaID, Path: setting.Path, Key: setting.Key,
			State: setting.State, Value: setting.Value,
		}
		if err := entry.Validate(); err != nil {
			return violation(ErrInvalidRecord, "segments.settings", "unsupported")
		}
		key := setting.SchemaID + "\x00" + setting.Path + "\x00" + setting.Key
		if index > 0 {
			if key == previous {
				return violation(ErrInvalidRecord, "segments.settings", "duplicate")
			}
			if key < previous {
				return violation(ErrInvalidRecord, "segments.settings", "order")
			}
		}
		previous = key
	}
	return nil
}

func validateSegmentList(segments []SnapshotSegment) error {
	if len(segments) == 0 {
		return violation(ErrInvalidRecord, "segments", "empty")
	}
	if len(segments) > MaxSnapshotSettings {
		return violation(ErrInvalidRecord, "segments", "count")
	}
	previous := ""
	for index, segment := range segments {
		if index > 0 {
			if segment.Target.ID == previous {
				return violation(ErrInvalidRecord, "segments.target", "duplicate")
			}
			if segment.Target.ID < previous {
				return violation(ErrInvalidRecord, "segments.target", "order")
			}
		}
		if err := validateSegment(segment); err != nil {
			return err
		}
		previous = segment.Target.ID
	}
	return nil
}

func encodeSnapshotSettings(settings []SnapshotSetting) []any {
	encoded := make([]any, 0, len(settings))
	for _, setting := range settings {
		value := map[string]any{}
		if setting.Value != nil {
			value = map[string]any{"type": setting.Value.Type, "text": setting.Value.Text}
		}
		encoded = append(encoded, map[string]any{
			"schemaId": setting.SchemaID,
			"path":     setting.Path,
			"key":      setting.Key,
			"state":    string(setting.State),
			"value":    value,
		})
	}
	return encoded
}

func decodeSnapshotSettings(value any) ([]SnapshotSetting, error) {
	items, ok := value.([]any)
	if !ok {
		return nil, violation(ErrInvalidRecord, "segments.settings", "type")
	}
	settings := make([]SnapshotSetting, 0, len(items))
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			return nil, violation(ErrInvalidRecord, "segments.settings", "type")
		}
		if err := exactKeys(object, "schemaId", "path", "key", "state", "value"); err != nil {
			return nil, err
		}
		schemaID, ok := object["schemaId"].(string)
		if !ok {
			return nil, violation(ErrInvalidRecord, "segments.settings.schemaId", "type")
		}
		settingsPath, ok := object["path"].(string)
		if !ok {
			return nil, violation(ErrInvalidRecord, "segments.settings.path", "type")
		}
		key, ok := object["key"].(string)
		if !ok {
			return nil, violation(ErrInvalidRecord, "segments.settings.key", "type")
		}
		state, ok := object["state"].(string)
		if !ok {
			return nil, violation(ErrInvalidRecord, "segments.settings.state", "type")
		}
		valueObject, ok := object["value"].(map[string]any)
		if !ok {
			return nil, violation(ErrInvalidRecord, "segments.settings.value", "type")
		}
		var parsedValue *model.VariantValue
		if len(valueObject) != 0 {
			if err := exactKeys(valueObject, "type", "text"); err != nil {
				return nil, err
			}
			valueType, ok := valueObject["type"].(string)
			if !ok {
				return nil, violation(ErrInvalidRecord, "segments.settings.value.type", "type")
			}
			text, ok := valueObject["text"].(string)
			if !ok {
				return nil, violation(ErrInvalidRecord, "segments.settings.value.text", "type")
			}
			parsedValue = &model.VariantValue{Type: valueType, Text: text}
		}
		settings = append(settings, SnapshotSetting{
			SchemaID: schemaID, Path: settingsPath, Key: key,
			State: model.SettingState(state), Value: parsedValue,
		})
	}
	return settings, nil
}

func encodeSegments(segments []SnapshotSegment) ([]any, error) {
	encoded := make([]any, 0, len(segments))
	for _, segment := range segments {
		value, err := encodeSegment(segment)
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, value)
	}
	return encoded, nil
}

func encodeSegment(segment SnapshotSegment) (map[string]any, error) {
	if err := validateSegment(segment); err != nil {
		return nil, err
	}
	value := map[string]any{
		"target": encodeSnapshotTargets([]model.Target{segment.Target})[0],
		"form":   string(segment.Form),
	}
	switch segment.Form {
	case SegmentFormEntries:
		entries, err := encodeSnapshotEntries(segment.Entries)
		if err != nil {
			return nil, err
		}
		value["entries"] = entries
	case SegmentFormSettings:
		value["settings"] = encodeSnapshotSettings(segment.Settings)
	case SegmentFormPacked:
		blobCID, err := castCID(segment.Blob.CID, cid.Raw, "segments.blob.ref")
		if err != nil {
			return nil, err
		}
		value["blob"] = atdata.Blob{
			Ref:      atdata.CIDLink(blobCID),
			MimeType: segment.Blob.MIMEType,
			Size:     int64(segment.Blob.Size),
		}
	}
	return value, nil
}

func decodeSegments(value any) ([]SnapshotSegment, error) {
	items, ok := value.([]any)
	if !ok {
		return nil, violation(ErrInvalidRecord, "segments", "type")
	}
	segments := make([]SnapshotSegment, 0, len(items))
	for _, item := range items {
		segment, err := decodeSegment(item)
		if err != nil {
			return nil, err
		}
		segments = append(segments, segment)
	}
	return segments, nil
}

func decodeSegment(value any) (SnapshotSegment, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return SnapshotSegment{}, violation(ErrInvalidRecord, "segments", "type")
	}
	form, ok := object["form"].(string)
	if !ok {
		return SnapshotSegment{}, violation(ErrInvalidRecord, "segments.form", "type")
	}
	keys := []string{"target", "form"}
	switch SegmentForm(form) {
	case SegmentFormEntries:
		keys = append(keys, "entries")
	case SegmentFormSettings:
		keys = append(keys, "settings")
	case SegmentFormPacked:
		keys = append(keys, "blob")
	default:
		return SnapshotSegment{}, violation(ErrInvalidRecord, "segments.form", "unsupported")
	}
	if err := exactKeys(object, keys...); err != nil {
		return SnapshotSegment{}, err
	}
	targets, err := decodeSnapshotTargets([]any{object["target"]})
	if err != nil || len(targets) != 1 {
		return SnapshotSegment{}, violation(ErrInvalidRecord, "segments.target", "unsupported")
	}
	segment := SnapshotSegment{Target: targets[0], Form: SegmentForm(form)}
	switch segment.Form {
	case SegmentFormEntries:
		entries, err := decodeSnapshotEntries(object["entries"])
		if err != nil {
			return SnapshotSegment{}, err
		}
		segment.Entries = entries
	case SegmentFormSettings:
		settings, err := decodeSnapshotSettings(object["settings"])
		if err != nil {
			return SnapshotSegment{}, err
		}
		segment.Settings = settings
	case SegmentFormPacked:
		blob, ok := object["blob"].(atdata.Blob)
		if !ok {
			return SnapshotSegment{}, violation(ErrInvalidRecord, "segments.blob", "type")
		}
		if blob.MimeType != SnapshotBlobMIMEType || blob.Size <= 0 || uint64(blob.Size) > MaxBlobBytes {
			return SnapshotSegment{}, violation(ErrInvalidRecord, "segments.blob", "unsupported")
		}
		blobCID, err := validateCID(blob.Ref.CID().Bytes(), cid.Raw, "segments.blob.ref")
		if err != nil {
			return SnapshotSegment{}, err
		}
		segment.Blob = BlobReference{
			CID: blobCID.Bytes(), Size: uint64(blob.Size), MIMEType: blob.MimeType,
		}
	}
	if err := validateSegment(segment); err != nil {
		return SnapshotSegment{}, err
	}
	return segment, nil
}

func (record SnapshotRecord) SegmentEntries() ([]SnapshotEntry, bool) {
	if len(record.Segments) != 1 || record.Segments[0].Form != SegmentFormEntries {
		return nil, false
	}
	return record.Segments[0].Entries, true
}

func (record SnapshotRecord) SegmentBlob() (BlobReference, bool) {
	if len(record.Segments) != 1 || record.Segments[0].Form != SegmentFormPacked {
		return BlobReference{}, false
	}
	return record.Segments[0].Blob, true
}

func (record SnapshotRecord) BlobReference() BlobReference {
	blob, _ := record.SegmentBlob()
	return blob
}

func (record SnapshotRecord) EntriesOrNil() []SnapshotEntry {
	entries, _ := record.SegmentEntries()
	return entries
}

type settingsDigestEntry struct {
	SchemaID string              `json:"schemaId"`
	Path     string              `json:"path"`
	Key      string              `json:"key"`
	State    model.SettingState  `json:"state"`
	Value    *model.VariantValue `json:"value,omitempty"`
}

func SettingsDigest(settings []SnapshotSetting) [32]byte {
	entries := make([]settingsDigestEntry, 0, len(settings))
	for _, setting := range settings {
		entries = append(entries, settingsDigestEntry{
			SchemaID: setting.SchemaID, Path: setting.Path, Key: setting.Key,
			State: setting.State, Value: setting.Value,
		})
	}
	encoded, err := json.Marshal(entries)
	if err != nil {
		return [32]byte{}
	}
	return sha256.Sum256(append([]byte("systems.lamb.dottie.snapshot-settings.v1\n"), encoded...))
}
