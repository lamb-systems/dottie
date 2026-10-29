package state

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/lamb-systems/dottie/internal/model"
)

const LatestSchemaVersion = 1
const PayloadRetention = "Referenced payloads are retained indefinitely; unreferenced-payload collection is not implemented."

var ErrStateLocked = errors.New("state is already locked")
var ErrUnsupportedSchema = errors.New("unsupported state schema")
var ErrTargetBindingChanged = errors.New("target binding changed")

type TargetDescriptor struct {
	ID            string
	Version       uint32
	Source        model.SourceKind
	SourceVersion uint32
	LogicalBase   model.RootBase
	LogicalPath   string
	Kind          model.SelectionKind
	Mode          string
	CreatedAt     int64
}

func (d TargetDescriptor) Validate() error {
	if d.Version != 1 {
		return errors.New("unsupported target descriptor version")
	}
	if d.Mode != "auto-apply" && d.Mode != "review" && d.Mode != "backup-only" {
		return errors.New("invalid target mode")
	}
	target := model.Target{ID: d.ID, Source: d.Source, SourceVersion: d.SourceVersion}
	switch d.Source {
	case model.SourceFiles:
		target.Root = &model.FileRoot{Base: d.LogicalBase, Path: d.LogicalPath, Kind: d.Kind}
	case model.SourceGNOME:
		if d.LogicalBase != "" || d.LogicalPath != "" || d.Kind != "" {
			return errors.New("GNOME target cannot carry a filesystem descriptor")
		}
	default:
		return errors.New("unsupported target source")
	}
	return target.Validate()
}

type Fingerprint struct {
	State      string
	Kind       model.FileKind
	Mode       uint32
	LinkTarget string
	ValueType  string
	ValueText  string
	Size       int64
	Digest     string
}

func NewFingerprint(state string, kind model.FileKind, mode uint32, linkTarget, valueType, valueText string, payload []byte) Fingerprint {
	digest := sha256.Sum256(payload)
	return Fingerprint{State: state, Kind: kind, Mode: mode, LinkTarget: linkTarget, ValueType: valueType, ValueText: valueText, Size: int64(len(payload)), Digest: hex.EncodeToString(digest[:])}
}

func (f Fingerprint) Validate(identity model.EntryKey) error {
	if f.Size < 0 || len(f.Digest) != sha256.Size*2 {
		return errors.New("invalid fingerprint size or digest")
	}
	if decoded, err := hex.DecodeString(f.Digest); err != nil || len(decoded) != sha256.Size || strings.ToLower(f.Digest) != f.Digest {
		return errors.New("invalid fingerprint digest")
	}
	if err := identity.Validate(); err != nil {
		return err
	}
	switch identity.Source {
	case model.SourceFiles:
		switch f.State {
		case string(model.FilePresent):
			switch f.Kind {
			case model.FileRegular:
				if f.LinkTarget != "" || f.ValueType != "" || f.ValueText != "" || f.Mode&^uint32(0o777) != 0 {
					return errors.New("invalid regular-file fingerprint")
				}
			case model.FileDirectory:
				if f.LinkTarget != "" || f.ValueType != "" || f.ValueText != "" || f.Mode&^uint32(0o777) != 0 || f.Size != 0 {
					return errors.New("invalid directory fingerprint")
				}
			case model.FileSymlink:
				if f.Mode != 0 || f.ValueType != "" || f.ValueText != "" || f.Size != 0 {
					return errors.New("invalid symlink fingerprint")
				}
				if err := (model.FileEntry{Path: identity.FilePath, State: model.FilePresent, Kind: model.FileSymlink, LinkTarget: f.LinkTarget}).Validate(); err != nil {
					return err
				}
			default:
				return errors.New("invalid present-file fingerprint kind")
			}
		case string(model.FileDeleted):
			if f.Kind != "" || f.Mode != 0 || f.LinkTarget != "" || f.ValueType != "" || f.ValueText != "" || f.Size != 0 {
				return errors.New("invalid deleted-file fingerprint")
			}
		default:
			return errors.New("invalid file fingerprint state")
		}
	case model.SourceGNOME:
		if f.Kind != "" || f.Mode != 0 || f.LinkTarget != "" {
			return errors.New("invalid setting fingerprint fields")
		}
		switch f.State {
		case "present":
			if f.ValueType == "" || f.ValueText == "" {
				return errors.New("present setting fingerprint requires a typed value")
			}
			value := &model.VariantValue{Type: f.ValueType, Text: f.ValueText}
			if err := (model.SettingEntry{SchemaID: identity.SchemaID, Path: identity.SettingsPath, Key: identity.SettingKey, State: model.SettingPresent, Value: value}).Validate(); err != nil {
				return err
			}
		case "reset":
			if f.ValueType != "" || f.ValueText != "" || f.Size != 0 {
				return errors.New("reset setting fingerprint cannot carry a value")
			}
			if err := (model.SettingEntry{SchemaID: identity.SchemaID, Path: identity.SettingsPath, Key: identity.SettingKey, State: model.SettingReset}).Validate(); err != nil {
				return err
			}
		default:
			return errors.New("invalid setting fingerprint state")
		}
	default:
		return errors.New("unsupported fingerprint source")
	}
	return nil
}

type BaseRecord struct {
	Identity    model.EntryKey
	Fingerprint Fingerprint
	PayloadRef  string
	RecordedAt  int64
}

type Intent struct {
	ID         string
	Identity   model.EntryKey
	PayloadRef string
	State      string
	Attempts   int
	CreatedAt  int64
}

type Conflict struct {
	ID               string
	Identity         model.EntryKey
	LocalPayloadRef  string
	RemotePayloadRef string
	State            string
	CreatedAt        int64
}

type Checkpoint struct {
	ID         string
	Counter    int64
	CID        string
	RecordedAt int64
}

type JournalEntry struct {
	ID        string
	Operation string
	State     string
	Identity  model.EntryKey
	Preimage  Fingerprint
	Postimage Fingerprint
	BackupRef string
	CreatedAt int64
}

func validateID(value, name string) error {
	if value == "" || strings.IndexByte(value, 0) >= 0 {
		return fmt.Errorf("invalid %s", name)
	}
	return nil
}

func validateIdentity(targetID string, identity model.EntryKey) error {
	if err := identity.Validate(); err != nil {
		return err
	}
	if identity.TargetID != targetID {
		return errors.New("entry identity target does not match record target")
	}
	return nil
}
