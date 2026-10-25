package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/dottorblaster/dottie/internal/model"
)

type wireManifest struct {
	Version         uint32         `json:"version"`
	Codec           string         `json:"codec"`
	SnapshotVersion uint32         `json:"snapshot_version"`
	Targets         []model.Target `json:"targets"`
	Entries         []wireEntry    `json:"entries"`
}

type wireEntry struct {
	TargetID   string              `json:"target_id"`
	Source     model.SourceKind    `json:"source"`
	Path       string              `json:"path,omitempty"`
	SchemaID   string              `json:"schema_id,omitempty"`
	Key        string              `json:"key,omitempty"`
	State      string              `json:"state"`
	Kind       model.FileKind      `json:"kind,omitempty"`
	Mode       uint32              `json:"mode,omitempty"`
	LinkTarget string              `json:"link_target,omitempty"`
	Value      *model.VariantValue `json:"value,omitempty"`
	Size       int64               `json:"size"`
	SHA256     string              `json:"sha256"`
	Member     string              `json:"member"`
}

func encodeManifest(manifest wireManifest) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(manifest); err != nil {
		return nil, err
	}
	encoded := buffer.Bytes()
	return bytes.Clone(encoded[:len(encoded)-1]), nil
}

func decodeManifest(data []byte) (wireManifest, error) {
	var manifest wireManifest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return wireManifest{}, fmt.Errorf("invalid snapshot manifest: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return wireManifest{}, errors.New("snapshot manifest contains multiple JSON values")
		}
		return wireManifest{}, fmt.Errorf("invalid trailing manifest data: %w", err)
	}
	canonical, err := encodeManifest(manifest)
	if err != nil {
		return wireManifest{}, fmt.Errorf("cannot canonicalize snapshot manifest: %w", err)
	}
	if !bytes.Equal(canonical, data) {
		return wireManifest{}, errors.New("snapshot manifest is not canonical JSON")
	}
	return manifest, nil
}

func wireFromEntry(entry model.Entry, member string) (wireEntry, []byte, error) {
	wire := wireEntry{TargetID: entry.TargetID, Member: member}
	switch {
	case entry.File != nil:
		file := entry.File
		wire.Source = model.SourceFiles
		wire.Path = file.Path
		wire.State = string(file.State)
		wire.Kind = file.Kind
		wire.Mode = file.Mode
		wire.LinkTarget = file.LinkTarget
		if file.State == model.FilePresent && file.Kind == model.FileRegular {
			return setWirePayload(wire, file.Content), file.Content, nil
		}
		return setWirePayload(wire, nil), nil, nil
	case entry.Setting != nil:
		setting := entry.Setting
		wire.Source = model.SourceGNOME
		wire.Path = setting.Path
		wire.SchemaID = setting.SchemaID
		wire.Key = setting.Key
		wire.State = string(setting.State)
		wire.Value = setting.Value
		return setWirePayload(wire, nil), nil, nil
	default:
		return wireEntry{}, nil, errors.New("entry has no representable source payload")
	}
}

func setWirePayload(wire wireEntry, payload []byte) wireEntry {
	wire.Size = int64(len(payload))
	wire.SHA256 = digestHex(payload)
	return wire
}

func entryFromWire(wire wireEntry, payload []byte) (model.Entry, error) {
	entry := model.Entry{TargetID: wire.TargetID}
	switch wire.Source {
	case model.SourceFiles:
		entry.File = &model.FileEntry{
			Path:       wire.Path,
			State:      model.FileState(wire.State),
			Kind:       wire.Kind,
			Content:    payload,
			Mode:       wire.Mode,
			LinkTarget: wire.LinkTarget,
		}
		if entry.File.State != model.FilePresent || entry.File.Kind != model.FileRegular {
			entry.File.Content = nil
			if len(payload) != 0 {
				return entry, errors.New("non-regular file manifest entry has a payload")
			}
		}
		if wire.SchemaID != "" || wire.Key != "" || wire.Value != nil {
			return entry, errors.New("file manifest entry contains settings fields")
		}
	case model.SourceGNOME:
		entry.Setting = &model.SettingEntry{
			SchemaID: wire.SchemaID,
			Path:     wire.Path,
			Key:      wire.Key,
			State:    model.SettingState(wire.State),
			Value:    wire.Value,
		}
		if len(payload) != 0 {
			return entry, errors.New("settings manifest entry has a payload member")
		}
		if wire.Kind != "" || wire.Mode != 0 || wire.LinkTarget != "" {
			return entry, errors.New("settings manifest entry contains file fields")
		}
	default:
		return model.Entry{TargetID: wire.TargetID}, fmt.Errorf("unsupported manifest entry source %q", wire.Source)
	}
	return entry, nil
}
